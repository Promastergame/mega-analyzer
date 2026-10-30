defmodule OmnisecServer.ErrorJSON do
  @moduledoc false

  # Catch-all renderer for HTTP errors raised inside the server.
  # Returns a tiny JSON envelope so callers always get parseable output.

  def render(template, _assigns) do
    %{ok: false, error: status_message_from_template(template)}
  end

  @doc "Maps a `\"404.json\"`-style template (or status code) to a reason phrase."
  @spec status_message_from_template(String.t() | pos_integer()) :: String.t()
  def status_message_from_template(template) when is_binary(template) do
    template
    |> String.split(".")
    |> hd()
    |> parse_status()
    |> reason_phrase()
  end

  def status_message_from_template(status) when is_integer(status),
    do: reason_phrase(status)

  defp parse_status(str) do
    case Integer.parse(str) do
      {code, ""} -> code
      _ -> 500
    end
  end

  # Reason phrases for the statuses this server emits (mirrors
  # `Plug.Conn.Status.reason_phrase/1` for our subset).
  defp reason_phrase(400), do: "Bad Request"
  defp reason_phrase(401), do: "Unauthorized"
  defp reason_phrase(403), do: "Forbidden"
  defp reason_phrase(404), do: "Not Found"
  defp reason_phrase(406), do: "Not Acceptable"
  defp reason_phrase(413), do: "Request Entity Too Large"
  defp reason_phrase(500), do: "Internal Server Error"
  defp reason_phrase(503), do: "Service Unavailable"
  defp reason_phrase(_), do: "Internal Server Error"
end
