resource "google_compute_firewall" "restricted" {
  name          = "restricted-admin"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["10.0.0.0/24"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_kms_crypto_key" "app" {
  name            = "app"
  key_ring        = "example"
  rotation_period = "7776000s"
}
