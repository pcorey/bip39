defmodule Bip39MnemonicTest do
  use ExUnit.Case
  use ExUnitProperties

  property "encodes and decodes mnemonics" do
    check all bytes <- binary(min_length: 16, max_length: 32),
              bits_to_truncate = bytes |> bit_size |> rem(32),
              <<_::size(bits_to_truncate), data::bits>> = bytes do
      {:ok, mnemonic} = Bip39.Mnemonic.encode(data)
      assert Bip39.Mnemonic.decode(mnemonic) == {:ok, data}
    end
  end

  property "rejects short binaries" do
    check all bits <- integer(1..8),
              <<_::size(bits), data::bits>> <- binary(max_length: 16) do
      assert Bip39.Mnemonic.encode(data) == {:error, :invalid_data}
    end
  end

  property "rejects long binaries" do
    check all bits <- integer(1..8),
              bytes <- binary(min_length: 32),
              data = <<bytes::binary, 0::size(bits)>> do
      assert Bip39.Mnemonic.encode(data) == {:error, :invalid_data}
    end
  end

  property "rejects misaligned binaries" do
    check all data <- bitstring(min_length: 129, max_length: 256),
              data |> bit_size |> rem(32) != 0 do
      assert Bip39.Mnemonic.encode(data) == {:error, :invalid_data}
    end
  end
end
