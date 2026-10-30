defmodule OmnisecServer.JSON do
  @moduledoc """
  Dependency-free JSON codec — in-house replacement for Jason.

  Covers exactly the surface this codebase uses: plain maps / lists /
  strings / numbers / booleans / nil, `encode(!)`, `encode_to_iodata(!)`
  (required by `Phoenix.Controller.json/2`) and `decode(!)`.

  Deliberate divergences from Jason:
    * no `Jason.Encoder` protocol — structs raise `EncodeError`
      (nothing in this codebase encodes structs);
    * decode options are accepted and ignored (we always return
      string keys, which is all callers expect);
    * floats use `Float.to_string/1` (shortest round-trip).

  There are no JSON dependencies left: this codec serves `Conn.json/2`,
  the controllers, the WebSocket server and the NIF bridges.
  """
  import Bitwise, only: [<<<: 2]

  defmodule DecodeError do
    @moduledoc "Raised by `decode!/2` (and returned by `decode/2`) on malformed input."
    defexception [:message, :position, :token]

    @impl true
    def exception(opts) do
      position = Keyword.get(opts, :position, 0)
      token = Keyword.get(opts, :token)

      message =
        Keyword.get_lazy(opts, :message, fn ->
          if token do
            "unexpected token at position #{position}: #{inspect(token)}"
          else
            "unexpected end of input at position #{position}"
          end
        end)

      %__MODULE__{message: message, position: position, token: token}
    end
  end

  defmodule EncodeError do
    @moduledoc "Raised by `encode!/2` for values with no JSON representation."
    defexception [:message, :value]

    @impl true
    def exception(opts) do
      value = Keyword.get(opts, :value)

      message =
        Keyword.get_lazy(opts, :message, fn -> "unable to encode value: #{inspect(value)}" end)

      %__MODULE__{message: message, value: value}
    end
  end

  @doc "Encodes `term` to a JSON binary. Mirrors `Jason.encode/2`."
  @spec encode(term(), keyword()) :: {:ok, binary()} | {:error, EncodeError.t()}
  def encode(term, _opts \\ []) do
    {:ok, IO.iodata_to_binary(encode_iodata(term))}
  rescue
    e in EncodeError -> {:error, e}
  end

  @doc "Encodes `term` to a JSON binary, raising on failure. Mirrors `Jason.encode!/2`."
  @spec encode!(term(), keyword()) :: binary()
  def encode!(term, _opts \\ []), do: IO.iodata_to_binary(encode_iodata(term))

  @doc "Encodes `term` to iodata. Mirrors `Jason.encode_to_iodata/2`."
  @spec encode_to_iodata(term(), keyword()) :: {:ok, iodata()} | {:error, EncodeError.t()}
  def encode_to_iodata(term, _opts \\ []) do
    {:ok, encode_iodata(term)}
  rescue
    e in EncodeError -> {:error, e}
  end

  @doc "Encodes `term` to iodata, raising on failure. Used by `Conn.json/2`."
  @spec encode_to_iodata!(term(), keyword()) :: iodata()
  def encode_to_iodata!(term, _opts \\ []), do: encode_iodata(term)

  @doc "Decodes a JSON binary with string keys. Mirrors `Jason.decode/2`."
  @spec decode(binary(), keyword()) :: {:ok, term()} | {:error, DecodeError.t()}
  def decode(binary, _opts \\ []) when is_binary(binary) do
    if String.valid?(binary) do
      try do
        {term, rest} = binary |> skip_ws() |> parse_value(binary)
        case skip_ws(rest) do
          "" -> {:ok, term}
          _ -> {:error, %DecodeError{position: position(binary, rest), token: rest}}
        end
      catch
        {:json_error, pos, token} -> {:error, %DecodeError{position: pos, token: token}}
      end
    else
      {:error, %DecodeError{message: "invalid UTF-8 in JSON input", position: 0}}
    end
  end

  @doc "Decodes a JSON binary, raising `DecodeError` on failure. Mirrors `Jason.decode!/2`."
  @spec decode!(binary(), keyword()) :: term()
  def decode!(binary, opts \\ []) do
    case decode(binary, opts) do
      {:ok, term} -> term
      {:error, e} -> raise e
    end
  end

  # ---------------------------------------------------------------------------
  # Decoder
  # ---------------------------------------------------------------------------

  defp position(original, rest), do: byte_size(original) - byte_size(rest)

  defp fail(original, rest, token \\ nil) do
    throw({:json_error, position(original, rest), token})
  end

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(bin), do: bin

  defp parse_value("", original), do: fail(original, "")
  defp parse_value(<<?", _::binary>> = bin, original), do: parse_string(bin, original)
  defp parse_value(<<?{, _::binary>> = bin, original), do: parse_object(bin, original)
  defp parse_value(<<?[, _::binary>> = bin, original), do: parse_array(bin, original)
  defp parse_value(<<"true", rest::binary>>, _original), do: {true, rest}
  defp parse_value(<<"false", rest::binary>>, _original), do: {false, rest}
  defp parse_value(<<"null", rest::binary>>, _original), do: {nil, rest}
  defp parse_value(<<c, _::binary>> = bin, original) when c == ?- or (c >= ?0 and c <= ?9) do
    parse_number(bin, original)
  end
  defp parse_value(bin, original), do: fail(original, bin)

  # --- strings ---

  defp parse_string(<<?", rest::binary>>, original), do: parse_string_content(rest, original, [])

  defp parse_string_content(<<?", rest::binary>>, _original, acc) do
    {IO.iodata_to_binary(Enum.reverse(acc)), rest}
  end

  defp parse_string_content(<<?\\, rest::binary>>, original, acc) do
    case rest do
      <<?", r::binary>> -> parse_string_content(r, original, [?" | acc])
      <<?\\, r::binary>> -> parse_string_content(r, original, [?\\ | acc])
      <<?/, r::binary>> -> parse_string_content(r, original, [?/ | acc])
      <<?b, r::binary>> -> parse_string_content(r, original, [?\b | acc])
      <<?f, r::binary>> -> parse_string_content(r, original, [?\f | acc])
      <<?n, r::binary>> -> parse_string_content(r, original, [?\n | acc])
      <<?r, r::binary>> -> parse_string_content(r, original, [?\r | acc])
      <<?t, r::binary>> -> parse_string_content(r, original, [?\t | acc])
      <<?u, r::binary>> -> parse_unicode_escape(r, original, acc)
      _ -> fail(original, rest)
    end
  end

  # Raw codepoint >= 0x20 (input already validated as UTF-8 by decode/2).
  defp parse_string_content(<<cp::utf8, rest::binary>>, original, acc) when cp >= 0x20 do
    parse_string_content(rest, original, [<<cp::utf8>> | acc])
  end

  defp parse_string_content(bin, original, _acc), do: fail(original, bin)

  defp parse_unicode_escape(<<a, b, c, d, rest::binary>>, original, acc) do
    with {:ok, hi} <- hex4(a, b, c, d) do
      cond do
        hi in 0xD800..0xDBFF ->
          case rest do
            <<?\\, ?u, a2, b2, c2, d2, rest2::binary>> ->
              with {:ok, lo} <- hex4(a2, b2, c2, d2),
                   true <- lo in 0xDC00..0xDFFF do
                cp = 0x10000 + ((hi - 0xD800) <<< 10) + (lo - 0xDC00)
                parse_string_content(rest2, original, [<<cp::utf8>> | acc])
              else
                _ -> fail(original, rest)
              end

            _ ->
              fail(original, rest)
          end

        hi in 0xDC00..0xDFFF ->
          fail(original, rest)

        true ->
          parse_string_content(rest, original, [<<hi::utf8>> | acc])
      end
    else
      _ -> fail(original, rest)
    end
  end

  defp parse_unicode_escape(bin, original, _acc), do: fail(original, bin)

  defp hex4(a, b, c, d) do
    with {:ok, x1} <- hex1(a),
         {:ok, x2} <- hex1(b),
         {:ok, x3} <- hex1(c),
         {:ok, x4} <- hex1(d) do
      {:ok, (x1 <<< 12) + (x2 <<< 8) + (x3 <<< 4) + x4}
    end
  end

  defp hex1(c) when c >= ?0 and c <= ?9, do: {:ok, c - ?0}
  defp hex1(c) when c >= ?a and c <= ?f, do: {:ok, c - ?a + 10}
  defp hex1(c) when c >= ?A and c <= ?F, do: {:ok, c - ?A + 10}
  defp hex1(_), do: :error

  # --- numbers: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? ---

  defp parse_number(bin, original) do
    {token, rest} = take_number_token(bin, [])

    case split_number_token(token) do
      {:int, int_part} ->
        {String.to_integer(int_part), rest}

      {:float, _} ->
        case Float.parse(token) do
          {f, ""} -> {f, rest}
          _ -> fail(original, bin)
        end

      :error ->
        fail(original, bin)
    end
  end

  defp take_number_token(<<c, rest::binary>>, acc)
       when c == ?- or c == ?+ or c == ?. or c == ?e or c == ?E or (c >= ?0 and c <= ?9) do
    take_number_token(rest, [c | acc])
  end

  defp take_number_token(bin, acc), do: {IO.iodata_to_binary(Enum.reverse(acc)), bin}

  defp split_number_token(token) do
    {sign, unsigned} =
      case token do
        "-" <> rest -> {"-", rest}
        _ -> {"", token}
      end

    with {:ok, int_digits, after_int} <- take_digits(unsigned),
         :ok <- validate_int_part(int_digits) do
      case after_int do
        "" ->
          {:int, sign <> int_digits}

        "." <> frac_rest ->
          with {:ok, frac_digits, after_frac} <- take_digits(frac_rest),
               true <- frac_digits != "",
               {:ok, after_exp} <- take_exponent(after_frac),
               true <- after_exp == "" do
            {:float, true}
          else
            _ -> :error
          end

        _ ->
          with {:ok, after_exp} <- take_exponent(after_int),
               true <- after_exp == "" do
            {:float, true}
          else
            _ -> :error
          end
      end
    else
      _ -> :error
    end
  end

  defp take_digits(bin), do: take_digits(bin, [])

  defp take_digits(<<c, rest::binary>>, acc) when c >= ?0 and c <= ?9 do
    take_digits(rest, [c | acc])
  end

  defp take_digits(bin, acc), do: {:ok, IO.iodata_to_binary(Enum.reverse(acc)), bin}

  defp validate_int_part(""), do: :error
  defp validate_int_part("0"), do: :ok
  defp validate_int_part(<<"0", _::binary>>), do: :error
  defp validate_int_part(_), do: :ok

  defp take_exponent(<<e, rest::binary>>) when e == ?e or e == ?E do
    unsigned =
      case rest do
        <<s, r::binary>> when s == ?+ or s == ?- -> r
        _ -> rest
      end

    with {:ok, digits, after_digits} <- take_digits(unsigned),
         true <- digits != "" do
      {:ok, after_digits}
    else
      _ -> :error
    end
  end

  defp take_exponent(bin), do: {:ok, bin}

  # --- objects ---

  defp parse_object(<<?{, rest::binary>>, original) do
    case skip_ws(rest) do
      <<?}, r::binary>> -> {%{}, r}
      r -> parse_object_members(r, original, %{})
    end
  end

  defp parse_object_members(bin, original, acc) do
    bin = skip_ws(bin)

    with <<?", _::binary>> <- bin,
         {key, r1} <- parse_string(bin, original),
         <<?:, r2::binary>> <- skip_ws(r1),
         {value, r3} <- r2 |> skip_ws() |> parse_value(original) do
      acc = Map.put_new(acc, key, value)

      case skip_ws(r3) do
        <<?,, r4::binary>> -> parse_object_members(r4, original, acc)
        <<?}, r4::binary>> -> {acc, r4}
        r -> fail(original, r)
      end
    else
      _ -> fail(original, bin)
    end
  end

  # --- arrays ---

  defp parse_array(<<?[, rest::binary>>, original) do
    case skip_ws(rest) do
      <<?], r::binary>> -> {[], r}
      r -> parse_array_elements(r, original, [])
    end
  end

  defp parse_array_elements(bin, original, acc) do
    {value, r1} = bin |> skip_ws() |> parse_value(original)

    case skip_ws(r1) do
      <<?,, r2::binary>> -> parse_array_elements(r2, original, [value | acc])
      <<?], r2::binary>> -> {Enum.reverse([value | acc]), r2}
      r -> fail(original, r)
    end
  end

  # ---------------------------------------------------------------------------
  # Encoder
  # ---------------------------------------------------------------------------

  defp encode_iodata(nil), do: "null"
  defp encode_iodata(true), do: "true"
  defp encode_iodata(false), do: "false"
  defp encode_iodata(term) when is_integer(term), do: Integer.to_string(term)

  defp encode_iodata(term) when is_float(term) do
    if term != term, do: raise(EncodeError, value: term)
    Float.to_string(term)
  end

  defp encode_iodata(term) when is_binary(term), do: encode_string(term)

  defp encode_iodata(term) when is_list(term) do
    [?[, encode_list(term), ?]]
  end

  defp encode_iodata(%_{} = struct) do
    raise EncodeError, value: struct
  end

  defp encode_iodata(term) when is_map(term) do
    [?{, encode_map(Map.to_list(term)), ?}]
  end

  defp encode_iodata(term), do: raise(EncodeError, value: term)

  defp encode_list([]), do: []
  defp encode_list([h | t]), do: [encode_iodata(h) | encode_list_rest(t)]

  defp encode_list_rest([]), do: []
  defp encode_list_rest([h | t]), do: [?, | [encode_iodata(h) | encode_list_rest(t)]]

  defp encode_map([]), do: []
  defp encode_map([{k, v} | t]), do: [[encode_key(k), ?:, encode_iodata(v)] | encode_map_rest(t)]

  defp encode_map_rest([]), do: []
  defp encode_map_rest([{k, v} | t]), do: [?, | [[encode_key(k), ?:, encode_iodata(v)] | encode_map_rest(t)]]

  defp encode_key(k) when is_binary(k), do: encode_string(k)
  defp encode_key(k) when is_atom(k), do: encode_string(Atom.to_string(k))
  defp encode_key(k) when is_integer(k), do: encode_string(Integer.to_string(k))
  defp encode_key(k), do: raise(EncodeError, value: k)

  defp encode_string(bin) do
    unless String.valid?(bin), do: raise(EncodeError, value: bin)
    [?", escape_string_content(bin), ?"]
  end

  defp escape_string_content(<<>>), do: []
  defp escape_string_content(<<?", rest::binary>>), do: ["\\\"" | escape_string_content(rest)]
  defp escape_string_content(<<?\\, rest::binary>>), do: ["\\\\" | escape_string_content(rest)]
  defp escape_string_content(<<?\b, rest::binary>>), do: ["\\b" | escape_string_content(rest)]
  defp escape_string_content(<<?\f, rest::binary>>), do: ["\\f" | escape_string_content(rest)]
  defp escape_string_content(<<?\n, rest::binary>>), do: ["\\n" | escape_string_content(rest)]
  defp escape_string_content(<<?\r, rest::binary>>), do: ["\\r" | escape_string_content(rest)]
  defp escape_string_content(<<?\t, rest::binary>>), do: ["\\t" | escape_string_content(rest)]
  defp escape_string_content(<<c, rest::binary>>) when c < 0x20, do: ["\\u00" <> hex2(c) | escape_string_content(rest)]
  defp escape_string_content(<<cp::utf8, rest::binary>>), do: [<<cp::utf8>> | escape_string_content(rest)]

  defp hex2(byte) do
    # Uppercase like Jason (`\u001F`), byte-identical output.
    Integer.to_string(byte, 16) |> String.pad_leading(2, "0") |> String.upcase()
  end
end
