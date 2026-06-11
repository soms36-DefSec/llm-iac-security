resource "google_storage_bucket_iam_binding" "public" {
  bucket  = "example-logs"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
