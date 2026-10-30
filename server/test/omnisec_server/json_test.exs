defmodule OmnisecServer.JSONTest do
  @moduledoc """
  Tests for the in-house `OmnisecServer.JSON` codec (zero dependencies —
  no oracle library, expectations are literals).
  """
  use ExUnit.Case, async: true

  alias OmnisecServer.JSON, as: J

  @valid_cases [
    {~s(null), nil},
    {~s(true), true},
    {~s(false), false},
    {~s(0), 0},
    {~s(-0), 0},
    {~s(42), 42},
    {~s(-17), -17},
    {~s(123456789012345678901234567890), 123_456_789_012_345_678_901_234_567_890},
    {~s(3.14), 3.14},
    {~s(-0.5), -0.5},
    {~s(1e3), 1000.0},
    {~s(1E-3), 0.001},
    {~s(2.5e+10), 2.5e10},
    {~s(""), ""},
    {~s("hello"), "hello"},
    {~s("a\\"b\\\\c\\/d\\be\\ff\\nh\\ri\\tj"), "a\"b\\c/d\be\ff\nh\ri\tj"},
    {~s("Cyrillic: \\u041f\\u0440\\u0438\\u0432\\u0435\\u0442"), "Cyrillic: Привет"},
    {~s("emoji pair: \\ud83d\\ude00"), "emoji pair: 😀"},
    {~s("lone BMP: \\u00e9\\u4e2d"), "lone BMP: é中"},
    {"\"raw utf8: Привет, мир! 📄\"", "raw utf8: Привет, мир! 📄"},
    {~s([]), []},
    {~s([1, "two", null, true, false, 3.5]), [1, "two", nil, true, false, 3.5]},
    {~s({}), %{}},
    {~s({"a": 1}), %{"a" => 1}},
    {~s({"a": {"b": {"c": [1, 2, {"d": null}]}}}), %{"a" => %{"b" => %{"c" => [1, 2, %{"d" => nil}]}}}},
    # Duplicate keys: first occurrence wins.
    {~s({"dup": 1, "dup": 2}), %{"dup" => 1}},
    {~s(  { \n "a"\t:\r\n [1 ,2 ] }  ), %{"a" => [1, 2]}},
    {~s({"empty_str": "", "empty_arr": [], "empty_obj": {}}),
     %{"empty_str" => "", "empty_arr" => [], "empty_obj" => %{}}}
  ]

  @invalid_cases [
    "",
    "   ",
    "{",
    "[",
    "{\"a\":}",
    "{\"a\"}",
    "{a: 1}",
    "[1,]",
    "[1 2]",
    "{\"a\": 1,}",
    "01",
    "-",
    "+1",
    "1.",
    ".5",
    "1e",
    "1e+",
    "0x10",
    "NaN",
    "Infinity",
    "tru",
    "nul",
    "\"unterminated",
    "\"bad \\x escape\"",
    "\"lone high surrogate \\ud83d\"",
    "\"lone low surrogate \\ude00\"",
    "\"bad surrogate tail \\ud83dx\"",
    "\"raw " <> <<0x01>> <> " control\"",
    "{\"a\": 1} trailing",
    "[1] [2]",
    "'single quotes'"
  ]

  test "decode accepts valid inputs" do
    for {input, expected} <- @valid_cases do
      assert {:ok, ^expected} = J.decode(input), "mismatch on #{inspect(input)}"
      assert expected == J.decode!(input)
    end
  end

  test "decode rejects invalid inputs" do
    for input <- @invalid_cases do
      assert {:error, %J.DecodeError{}} = J.decode(input),
             "ours accepted #{inspect(input)}"

      assert_raise J.DecodeError, fn -> J.decode!(input) end
    end
  end

  test "invalid UTF-8 is rejected" do
    bad = <<0x22, 0xFF, 0x22>>
    assert {:error, %J.DecodeError{}} = J.decode(bad)
  end

  test "encode round-trips" do
    terms = [
      nil,
      true,
      false,
      0,
      -42,
      10_000_000_000_000_000_000_000,
      3.14,
      -0.5,
      1.0e300,
      "",
      "plain",
      "quotes \" and \\ backslash",
      "controls \b\f\n\r\t" <> <<0x01, 0x1F>>,
      "unicode Привет 📄 中",
      [],
      [1, "two", nil, true, 3.5, []],
      %{},
      %{"a" => 1, "b" => [1, 2, %{"c" => nil}]}
    ]

    # Non-string keys stringify on encode, so these round-trip to
    # string-keyed maps instead of the input term.
    coerced = [
      {%{7 => "seven", "str" => 1, atom_key: "v"},
       %{"7" => "seven", "str" => 1, "atom_key" => "v"}},
      {%{nested: %{list: [%{deep: true}]}},
       %{"nested" => %{"list" => [%{"deep" => true}]}}}
    ]

    for term <- terms do
      assert {:ok, json} = J.encode(term)
      assert {:ok, ^term} = J.decode(json)
      assert term == J.decode!(json)
      assert json == J.encode!(term)
      assert {:ok, ^json} = term |> J.encode_to_iodata() |> then(fn {:ok, io} -> {:ok, IO.iodata_to_binary(io)} end)
      assert json == IO.iodata_to_binary(J.encode_to_iodata!(term))
    end

    for {term, back} <- coerced do
      assert {:ok, json} = J.encode(term)
      assert {:ok, ^back} = J.decode(json)
    end
  end

  test "encode emits compact bytes" do
    assert J.encode!(%{"a" => 1}) == ~s({"a":1})
    assert J.encode!([1, "two", nil, true]) == ~s([1,"two",null,true])
    assert J.encode!(%{"a" => 1, "b" => [1, 2, %{"c" => nil}]}) == ~s({"a":1,"b":[1,2,{"c":null}]})
    assert J.encode!(%{ok: true}) == ~s({"ok":true})
  end

  test "encode rejects non-JSON values" do
    assert {:error, %J.EncodeError{}} = J.encode({1, 2})
    assert {:error, %J.EncodeError{}} = J.encode(self())
    assert {:error, %J.EncodeError{}} = J.encode(%URI{path: "/"})
    assert {:error, %J.EncodeError{}} = J.encode(%{"k" => {1}})
    assert {:error, %J.EncodeError{}} = J.encode(<<0xFF, 0xFE>>)
    assert_raise J.EncodeError, fn -> J.encode!({1}) end
  end
end
