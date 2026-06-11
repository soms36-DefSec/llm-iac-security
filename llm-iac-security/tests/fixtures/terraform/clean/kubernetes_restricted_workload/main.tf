resource "kubernetes_pod" "app" {
  metadata {
    name = "app"
  }

  spec {
    host_network = false

    container {
      name  = "app"
      image = "nginx:1.25"

      security_context {
        privileged                 = false
        allow_privilege_escalation = false
        run_as_non_root            = true
        run_as_user                = 1000
        capabilities {
          drop = ["ALL"]
        }
      }
    }
  }
}
