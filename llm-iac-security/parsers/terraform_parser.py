"""Terraform HCL2 parser."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from config.logging_config import get_logger
from iac.models import IaCResource, IaCTemplate
from parsers.base_parser import BaseParser
from utils.exceptions import ParsingError, UnsupportedTemplateFormatError

logger = get_logger(__name__)


class TerraformParser(BaseParser):
    """Parses Terraform HCL2 files into the normalized IaC model."""

    def parse(self, path: str | Path) -> dict[str, Any]:
        """Parse a .tf file or a directory containing .tf files."""
        try:
            import hcl2
        except ImportError as exc:
            raise ParsingError("python-hcl2 is required to parse Terraform files.") from exc

        p = Path(path)
        tf_files = self._tf_files(p)
        if not tf_files:
            logger.warning("terraform_no_files", path=str(p))
            return {"files": [], "raw_content": "", "source_path": str(p)}

        parsed_files: list[dict[str, Any]] = []
        raw_parts: list[str] = []
        for tf_file in tf_files:
            logger.info("terraform_parse_started", path=str(tf_file))
            try:
                text = tf_file.read_text(encoding="utf-8")
                with tf_file.open("r", encoding="utf-8") as handle:
                    parsed = hcl2.load(handle) or {}
            except Exception as exc:
                raise ParsingError(f"Failed to parse Terraform file {tf_file}: {exc}") from exc
            line_metadata = _terraform_block_line_metadata(text)
            parsed_files.append({
                "path": str(tf_file),
                "content": parsed,
                "line_numbers": {
                    address: metadata["line_number"]
                    for address, metadata in line_metadata.items()
                },
                "line_metadata": line_metadata,
            })
            raw_parts.append(f"# File: {tf_file}\n{text}")

        return {"files": parsed_files, "raw_content": "\n\n".join(raw_parts), "source_path": str(p)}

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize parsed HCL2 into a shared IaC model."""
        resources: list[IaCResource] = []
        variables: dict[str, Any] = {}
        outputs: dict[str, Any] = {}
        providers: dict[str, Any] = {}
        locals_data: dict[str, Any] = {}

        # First pass: gather context used by expression evaluation.
        for parsed_file in raw.get("files", []):
            content = parsed_file.get("content", {})
            variables.update(_merge_named_blocks(content.get("variable", [])))
            outputs.update(_merge_named_blocks(content.get("output", [])))
            providers.update(_merge_named_blocks(content.get("provider", [])))
            for local_block in _as_list(content.get("locals", [])):
                if isinstance(local_block, dict):
                    locals_data.update(_clean_hcl_value(local_block))

        context = _EvaluationContext(variables=variables, locals_data={})
        for _ in range(5):
            previous_locals = locals_data
            locals_data = _evaluate_value(locals_data, context)
            context = _EvaluationContext(variables=variables, locals_data=locals_data)
            if locals_data == previous_locals:
                break
        outputs = _evaluate_value(outputs, context)

        # Second pass: normalize resources after variables and locals are known.
        for parsed_file in raw.get("files", []):
            source_file = parsed_file.get("path", "")
            line_metadata = parsed_file.get("line_metadata", {})
            content = parsed_file.get("content", {})
            resources.extend(self._resources_from_blocks(
                content.get("resource", []), source_file, "resource", line_metadata, context
            ))
            resources.extend(self._resources_from_blocks(
                content.get("data", []), source_file, "data", line_metadata, context
            ))

        template = IaCTemplate(
            iac_type="terraform",
            source_path=raw.get("source_path", ""),
            raw_content=raw.get("raw_content", ""),
            resources=resources,
            variables=variables,
            outputs=outputs,
            metadata={"providers": providers, "locals": locals_data},
        )
        normalized = template.to_dict()
        logger.info("terraform_normalized", resources=len(resources), source=raw.get("source_path", ""))
        return normalized

    def parse_and_normalize(self, path: str | Path) -> dict[str, Any]:
        """Parse and normalize a Terraform file or directory."""
        return self.normalize(self.parse(path))

    @staticmethod
    def _tf_files(path: Path) -> list[Path]:
        if path.is_dir():
            return sorted(item for item in path.rglob("*.tf") if item.is_file())
        if path.suffix.lower() != ".tf":
            raise UnsupportedTemplateFormatError(f"Unsupported Terraform extension: {path.suffix}")
        return [path]

    @staticmethod
    def _resources_from_blocks(
        blocks: Any,
        source_file: str,
        block_type: str,
        line_metadata: dict[str, dict[str, Any]],
        context: "_EvaluationContext",
    ) -> list[IaCResource]:
        resources: list[IaCResource] = []
        for block in _as_list(blocks):
            if not isinstance(block, dict):
                continue
            for raw_resource_type, named_resources in block.items():
                resource_type = _clean_label(raw_resource_type)
                if not isinstance(named_resources, dict):
                    continue
                for raw_name, properties in named_resources.items():
                    name = _clean_label(raw_name)
                    props = _evaluate_value(_clean_hcl_value(properties or {}), context)
                    address = f"{resource_type}.{name}" if block_type == "resource" else f"data.{resource_type}.{name}"
                    metadata = line_metadata.get(address, {})
                    resources.append(
                        IaCResource(
                            logical_id=address,
                            resource_type=resource_type,
                            provider=detect_provider(resource_type),
                            name=name,
                            properties=props,
                            source_file=source_file,
                            line_number=metadata.get("line_number"),
                            depends_on=_string_list(props.get("depends_on", [])),
                            metadata={
                                "block_type": block_type,
                                "property_line_numbers": metadata.get("property_line_numbers", {}),
                            },
                        )
                    )
        return resources


def detect_provider(resource_type: str) -> str:
    """Detect a Terraform provider from a resource type prefix."""
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_"):
        return "azure"
    if resource_type.startswith("google_") or resource_type.startswith("google_project_"):
        return "gcp"
    if resource_type.startswith("kubernetes_"):
        return "kubernetes"
    return "unknown"


def _merge_named_blocks(blocks: Any) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for block in _as_list(blocks):
        if isinstance(block, dict):
            merged.update({_clean_label(key): _clean_hcl_value(value) for key, value in block.items()})
    return merged


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value)]


def _clean_label(value: Any) -> str:
    return _strip_wrapping_quotes(str(value))


def _clean_hcl_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            _clean_label(key): _clean_hcl_value(child)
            for key, child in value.items()
            if not str(key).startswith("__")
        }
    if isinstance(value, list):
        return [_clean_hcl_value(item) for item in value]
    if isinstance(value, str):
        return _strip_wrapping_quotes(value)
    return value


def _strip_wrapping_quotes(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


class _EvaluationContext:
    """Small Terraform expression context for variables and locals."""

    def __init__(self, variables: dict[str, Any], locals_data: dict[str, Any]) -> None:
        self.variables = variables
        self.locals_data = locals_data

    def resolve_reference(self, expression: str) -> Any:
        expression = expression.strip()
        if expression.startswith("var."):
            return self._resolve_path(self.variables, expression.removeprefix("var."))
        if expression.startswith("local."):
            return self._resolve_path(self.locals_data, expression.removeprefix("local."))
        return None

    def _resolve_path(self, root: dict[str, Any], path: str) -> Any:
        tokens = _reference_tokens(path)
        if not tokens:
            return None
        value = root.get(str(tokens[0]))
        if isinstance(value, dict) and "default" in value:
            value = value["default"]
        for token in tokens[1:]:
            if isinstance(value, dict):
                value = value.get(str(token))
            elif isinstance(value, list) and isinstance(token, int) and 0 <= token < len(value):
                value = value[token]
            else:
                return None
        return value


def _evaluate_value(value: Any, context: _EvaluationContext) -> Any:
    """Evaluate simple Terraform expressions without pretending to be Terraform."""
    if isinstance(value, dict):
        return {_clean_label(key): _evaluate_value(child, context) for key, child in value.items()}
    if isinstance(value, list):
        return [_evaluate_value(item, context) for item in value]
    if not isinstance(value, str):
        return value

    text = _strip_wrapping_quotes(value)
    full_expression = _unwrap_interpolation(text)
    if full_expression is not None:
        evaluated = _evaluate_expression(full_expression, context)
        return evaluated if evaluated is not None else text

    direct_reference = context.resolve_reference(text)
    if direct_reference is not None:
        return direct_reference
    direct_expression = _evaluate_expression(text, context)
    if direct_expression is not None:
        return direct_expression

    return _INTERPOLATION_PATTERN.sub(
        lambda match: _stringify_interpolation(_evaluate_expression(match.group(1), context), match.group(0)),
        text,
    )


_INTERPOLATION_PATTERN = re.compile(r"\${\s*([^}]+)\s*}")


def _unwrap_interpolation(value: str) -> str | None:
    match = re.fullmatch(r"\${\s*(.+?)\s*}", value.strip(), re.DOTALL)
    return match.group(1) if match else None


def _evaluate_expression(expression: str, context: _EvaluationContext) -> Any:
    expression = expression.strip()
    full_expression = _unwrap_interpolation(expression)
    if full_expression is not None:
        return _evaluate_expression(full_expression, context)

    literal = _parse_literal(expression)
    if literal is not _UNRESOLVED:
        return literal

    conditional = _evaluate_conditional(expression, context)
    if conditional is not _UNRESOLVED:
        return conditional

    logical = _evaluate_logical(expression, context)
    if logical is not _UNRESOLVED:
        return logical

    comparison = _evaluate_comparison(expression, context)
    if comparison is not _UNRESOLVED:
        return comparison

    index_access = _evaluate_index_access(expression, context)
    if index_access is not _UNRESOLVED:
        return index_access

    resolved = context.resolve_reference(expression)
    if resolved is not None:
        return _evaluate_value(resolved, context)

    if expression.startswith("jsonencode(") and expression.endswith(")"):
        return _parse_jsonencode_expression(expression, context)

    function_value = _evaluate_function(expression, context)
    if function_value is not _UNRESOLVED:
        return function_value

    hcl_value = _parse_hcl_expression(expression, context)
    if hcl_value is not _UNRESOLVED:
        return hcl_value
    return None


def _stringify_interpolation(value: Any, fallback: str) -> str:
    """Render an interpolation replacement without losing falsey values."""
    if value is None:
        return fallback
    return str(value)


def _parse_jsonencode_expression(expression: str, context: _EvaluationContext) -> Any:
    body = expression.removeprefix("jsonencode(")[:-1].strip()
    body = _replace_references_in_expression(body, context)
    try:
        import hcl2
        import io

        parsed = hcl2.load(io.StringIO(f"locals {{ encoded = {body} }}"))
        locals_block = parsed.get("locals", [{}])[0]
        return _clean_hcl_value(locals_block.get("encoded", body))
    except Exception:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return expression


def _replace_references_in_expression(expression: str, context: _EvaluationContext) -> str:
    def replace(match: re.Match[str]) -> str:
        value = context.resolve_reference(match.group(0))
        if value is not None:
            return _to_hcl_literal(value)
        return match.group(0)

    return re.sub(r"\b(?:var|local)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+|\[[^\]]+\])*", replace, expression)


_UNRESOLVED = object()


def _parse_literal(expression: str) -> Any:
    text = expression.strip()
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", ""}:
        return None if lowered == "null" else _UNRESOLVED
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return _strip_wrapping_quotes(text)
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return _UNRESOLVED


def _evaluate_conditional(expression: str, context: _EvaluationContext) -> Any:
    split = _split_ternary(expression)
    if not split:
        return _UNRESOLVED
    condition, when_true, when_false = split
    condition_value = _evaluate_expression(condition, context)
    if condition_value is None:
        return _UNRESOLVED
    return _evaluate_expression(when_true if _bool_value(condition_value) else when_false, context)


def _evaluate_logical(expression: str, context: _EvaluationContext) -> Any:
    for operator in ("||", "&&"):
        split = _split_top_level_once(expression, operator)
        if split:
            left, right = split
            if operator == "||":
                return _bool_value(_evaluate_expression(left, context)) or _bool_value(_evaluate_expression(right, context))
            return _bool_value(_evaluate_expression(left, context)) and _bool_value(_evaluate_expression(right, context))
    if expression.startswith("!"):
        return not _bool_value(_evaluate_expression(expression[1:], context))
    return _UNRESOLVED


def _evaluate_comparison(expression: str, context: _EvaluationContext) -> Any:
    for operator in ("==", "!=", ">=", "<=", ">", "<"):
        split = _split_top_level_once(expression, operator)
        if not split:
            continue
        left = _evaluate_expression(split[0], context)
        right = _evaluate_expression(split[1], context)
        if left is None or right is None:
            return _UNRESOLVED
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        try:
            if operator == ">=":
                return left >= right
            if operator == "<=":
                return left <= right
            if operator == ">":
                return left > right
            if operator == "<":
                return left < right
        except TypeError:
            return _UNRESOLVED
    return _UNRESOLVED


def _evaluate_index_access(expression: str, context: _EvaluationContext) -> Any:
    split = _split_index_access(expression)
    if not split:
        return _UNRESOLVED
    base_expression, key_expression = split
    base = _evaluate_expression(base_expression, context)
    key = _evaluate_expression(key_expression, context)
    if isinstance(base, list) and isinstance(key, int) and 0 <= key < len(base):
        return base[key]
    if isinstance(base, dict) and key is not None:
        return base.get(str(key))
    return _UNRESOLVED


def _evaluate_function(expression: str, context: _EvaluationContext) -> Any:
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)\)", expression, re.DOTALL)
    if not match:
        return _UNRESOLVED
    name = match.group(1).lower()
    raw_args = _split_top_level_args(match.group(2))
    args = [_function_arg(arg, context) for arg in raw_args]
    if any(arg is _UNRESOLVED for arg in args):
        return _UNRESOLVED

    try:
        if name == "jsonencode":
            return _parse_jsonencode_expression(expression, context)
        if name == "jsondecode" and args:
            return json.loads(str(args[0]))
        if name == "lower" and args:
            return str(args[0]).lower()
        if name == "upper" and args:
            return str(args[0]).upper()
        if name == "trimspace" and args:
            return str(args[0]).strip()
        if name == "format" and args:
            return str(args[0]) % tuple(args[1:])
        if name == "join" and len(args) >= 2:
            return str(args[0]).join(str(item) for item in _as_list(args[1]))
        if name == "split" and len(args) >= 2:
            return str(args[1]).split(str(args[0]))
        if name == "concat":
            output: list[Any] = []
            for arg in args:
                output.extend(_as_list(arg))
            return output
        if name == "merge":
            merged: dict[str, Any] = {}
            for arg in args:
                if isinstance(arg, dict):
                    merged.update(arg)
            return merged
        if name == "lookup" and len(args) >= 2 and isinstance(args[0], dict):
            return args[0].get(str(args[1]), args[2] if len(args) > 2 else None)
        if name == "coalesce":
            return next((arg for arg in args if arg is not None and arg != ""), None)
        if name == "length" and args:
            return len(args[0])
        if name == "contains" and len(args) >= 2:
            return args[1] in _as_list(args[0])
        if name == "element" and len(args) >= 2:
            values = _as_list(args[0])
            index = int(args[1])
            return values[index % len(values)] if values else None
        if name == "startswith" and len(args) >= 2:
            return str(args[0]).startswith(str(args[1]))
        if name == "endswith" and len(args) >= 2:
            return str(args[0]).endswith(str(args[1]))
        if name == "replace" and len(args) >= 3:
            return str(args[0]).replace(str(args[1]), str(args[2]))
        if name in {"tolist", "toset"} and args:
            return _as_list(args[0])
        if name == "tomap" and args and isinstance(args[0], dict):
            return args[0]
        if name == "tostring" and args:
            return str(args[0])
        if name == "tonumber" and args:
            return float(args[0]) if "." in str(args[0]) else int(args[0])
        if name == "tobool" and args:
            return _bool_value(args[0])
    except (TypeError, ValueError, json.JSONDecodeError):
        return _UNRESOLVED
    return _UNRESOLVED


def _function_arg(expression: str, context: _EvaluationContext) -> Any:
    if expression.strip().lower() == "null":
        return None
    literal = _parse_literal(expression)
    if literal is not _UNRESOLVED:
        return literal
    value = _evaluate_expression(expression, context)
    if value is not None:
        return value
    hcl_value = _parse_hcl_expression(expression, context)
    if hcl_value is not _UNRESOLVED:
        return hcl_value
    if re.match(r"^(?:var|local)\.", expression.strip()) or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(", expression.strip()):
        return _UNRESOLVED
    return _strip_wrapping_quotes(expression.strip())


def _parse_hcl_expression(expression: str, context: _EvaluationContext) -> Any:
    text = expression.strip()
    if not text or text[0] not in "[{":
        return _UNRESOLVED
    try:
        import hcl2
        import io

        prepared = _replace_references_in_expression(text, context)
        parsed = hcl2.load(io.StringIO(f"locals {{ value = {prepared} }}"))
        value = parsed.get("locals", [{}])[0].get("value")
        return _evaluate_value(_clean_hcl_value(value), context)
    except Exception:
        return _UNRESOLVED


def _reference_tokens(path: str) -> list[str | int]:
    tokens: list[str | int] = []
    pattern = re.compile(r"([A-Za-z0-9_-]+)|\[(\"[^\"]+\"|'[^']+'|\d+)\]")
    for match in pattern.finditer(path):
        raw = match.group(1) or match.group(2)
        if raw is None:
            continue
        if raw.isdigit():
            tokens.append(int(raw))
        else:
            tokens.append(_strip_wrapping_quotes(raw.strip("\"'")))
    return tokens


def _to_hcl_literal(value: Any) -> str:
    return json.dumps(value)


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _split_ternary(expression: str) -> tuple[str, str, str] | None:
    question = _find_top_level_token(expression, "?")
    if question < 0:
        return None
    colon = _find_top_level_token(expression, ":", start=question + 1)
    if colon < 0:
        return None
    return expression[:question].strip(), expression[question + 1:colon].strip(), expression[colon + 1:].strip()


def _split_top_level_once(expression: str, operator: str) -> tuple[str, str] | None:
    index = _find_top_level_token(expression, operator)
    if index < 0:
        return None
    return expression[:index].strip(), expression[index + len(operator):].strip()


def _split_index_access(expression: str) -> tuple[str, str] | None:
    text = expression.strip()
    if not text.endswith("]"):
        return None
    depth = 0
    quote: str | None = None
    escape = False
    for index in range(len(text) - 1, -1, -1):
        char = text[index]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "]":
            depth += 1
        elif char == "[":
            depth -= 1
            if depth == 0 and index > 0:
                return text[:index].strip(), text[index + 1:-1].strip()
    return None


def _split_top_level_args(arguments: str) -> list[str]:
    args: list[str] = []
    start = 0
    for index in _top_level_delimiters(arguments, ","):
        args.append(arguments[start:index].strip())
        start = index + 1
    tail = arguments[start:].strip()
    if tail:
        args.append(tail)
    return args


def _find_top_level_token(expression: str, token: str, start: int = 0) -> int:
    for index in _top_level_delimiters(expression, token, start=start):
        return index
    return -1


def _top_level_delimiters(expression: str, token: str, start: int = 0) -> list[int]:
    indexes: list[int] = []
    depth = 0
    quote: str | None = None
    escape = False
    index = start
    while index < len(expression):
        char = expression[index]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and expression.startswith(token, index):
            indexes.append(index)
            index += len(token) - 1
        index += 1
    return indexes


def _terraform_block_line_numbers(text: str) -> dict[str, int]:
    """Map Terraform resource and data block addresses to their starting lines."""
    return {
        address: metadata["line_number"]
        for address, metadata in _terraform_block_line_metadata(text).items()
    }


def _terraform_block_line_metadata(text: str) -> dict[str, dict[str, Any]]:
    """Map Terraform resource and data blocks to block and property line numbers."""
    line_metadata: dict[str, dict[str, Any]] = {}
    block_pattern = re.compile(
        r'^[ \t]*(resource|data)\s+"([^"]+)"\s+"([^"]+)"',
        re.MULTILINE,
    )
    for match in block_pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        block_type, resource_type, name = match.groups()
        address = f"{resource_type}.{name}" if block_type == "resource" else f"data.{resource_type}.{name}"
        open_brace = text.find("{", match.end())
        close_brace = _find_matching_brace(text, open_brace)
        body = text[open_brace + 1:close_brace] if open_brace >= 0 and close_brace > open_brace else ""
        body_start_line = text.count("\n", 0, open_brace) + 1 if open_brace >= 0 else line
        line_metadata[address] = {
            "line_number": line,
            "property_line_numbers": _terraform_property_line_numbers(body, body_start_line),
        }
    return line_metadata


def _find_matching_brace(text: str, open_brace: int) -> int:
    if open_brace < 0:
        return -1
    depth = 0
    quote: str | None = None
    escape = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _terraform_property_line_numbers(body: str, start_line: int) -> dict[str, int]:
    """Best-effort mapping of Terraform property paths to source lines."""
    line_numbers: dict[str, int] = {}
    stack: list[str] = []
    for offset, line in enumerate(body.splitlines()):
        line_number = start_line + offset
        stripped = _strip_inline_comment(line).strip()
        if not stripped:
            continue

        leading_closures = len(stripped) - len(stripped.lstrip("}"))
        for _ in range(leading_closures):
            if stack:
                stack.pop()
        stripped = stripped.lstrip("}").strip()
        if not stripped:
            continue

        assignment = re.match(r"([A-Za-z0-9_-]+)\s*=", stripped)
        if assignment:
            key = assignment.group(1)
            path = ".".join([*stack, key])
            line_numbers.setdefault(path, line_number)
            if "{" in stripped[assignment.end():] and "}" not in stripped[assignment.end():]:
                stack.append(key)
            continue

        block = re.match(r"([A-Za-z0-9_-]+)(?:\s+\"[^\"]+\")*\s*\{", stripped)
        if block:
            key = block.group(1)
            path = ".".join([*stack, key])
            line_numbers.setdefault(path, line_number)
            if "}" not in stripped[block.end():]:
                stack.append(key)
    return line_numbers


def _strip_inline_comment(line: str) -> str:
    quote: str | None = None
    escape = False
    for index, char in enumerate(line):
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "#":
            return line[:index]
        elif char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return line[:index]
    return line
