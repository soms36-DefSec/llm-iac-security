resource "kubernetes_pod" "app" {
  metadata {
    name = "app"
  }

  spec {
    host_network = true

    container {
      name  = "app"
      image = "nginx:1.25"

      security_context {
        privileged                   = true
        allow_privilege_escalation   = true
        run_as_user                  = 0
        capabilities {
          add = ["SYS_ADMIN"]
        }
      }
    }
  }
}
