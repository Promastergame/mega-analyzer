defmodule Mix.Tasks.Gen.Cert do
  @moduledoc """
  Generates a self-signed TLS certificate for the local mock server.

  The certificate is for **local development only** (CN=localhost) and is written
  to `priv/cert/{cert,key}.pem`. These files are git-ignored and must never be
  committed — every developer generates their own.

      mix gen.cert

  Requires the `openssl` command-line tool to be available on PATH.
  """
  @shortdoc "Generate a local self-signed TLS cert (priv/cert/*.pem)"

  use Mix.Task

  @cert_dir Path.join(["priv", "cert"])

  @impl Mix.Task
  def run(_args) do
    File.mkdir_p!(@cert_dir)

    cert_file = Path.join(@cert_dir, "cert.pem")
    key_file = Path.join(@cert_dir, "key.pem")

    if File.exists?(cert_file) and File.exists?(key_file) do
      Mix.shell().info("Certificate already exists at #{@cert_dir}/. Delete the .pem files to regenerate.")
    else
      ensure_openssl!()

      Mix.shell().info("Generating self-signed localhost certificate in #{@cert_dir}/ ...")

      {_out, status} =
        System.cmd(
          "openssl",
          [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_file,
            "-out", cert_file,
            "-days", "365",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
          ],
          stderr_to_stdout: true
        )

      if status == 0 do
        Mix.shell().info("Done. Wrote #{cert_file} and #{key_file} (local dev only — do not commit).")
      else
        Mix.raise("openssl failed with exit status #{status}")
      end
    end
  end

  defp ensure_openssl! do
    unless System.find_executable("openssl") do
      Mix.raise("`openssl` not found on PATH. Install OpenSSL and re-run `mix gen.cert`.")
    end
  end
end
