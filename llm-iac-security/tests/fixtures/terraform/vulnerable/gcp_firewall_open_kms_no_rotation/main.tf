resource "google_compute_firewall" "open" {
  name          = "open-admin"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  allow {
    protocol = "all"
  }
}

resource "google_kms_crypto_key" "app" {
  name     = "app"
  key_ring = "example"
}
