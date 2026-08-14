# Local patches

This directory vendors `iroh-blobs` 0.103.0 until an upstream release includes
the same fix.

On Windows, complete blobs are served through `positioned_io::RandomAccessFile`.
The standard `File::read_at` implementation creates a file mapping for each
small read, which makes range downloads unnecessarily slow. The wrapper uses
`seek_read` while preserving the existing disk-backed storage and bounded read
buffers.
