resource "google_storage_bucket_iam_member" "private" {
  bucket = "example-logs"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:scanner@example.iam.gserviceaccount.com"
}
