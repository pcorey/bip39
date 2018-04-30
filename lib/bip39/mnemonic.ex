defmodule Bip39.Mnemonic do
  @wordlist Application.fetch_env!(
              :bip39,
              :wordlist
            )

  def generate do
    encode(generate_entropy)
  end

  def encode(data)
      when is_binary(data) and bit_size(data) >= 128 and bit_size(data) <= 256 and
             rem(bit_size(data), 32) == 0 do
    {:ok,
     data
     |> attach_checksum
     |> map_onto_wordlist}
  end

  def encode(_), do: {:error, :invalid_data}

  def decode(mnemonic) do
    data_and_checksum =
      mnemonic
      |> Enum.map(&Enum.find_index(@wordlist, fn w -> w == &1 end))
      |> Enum.reduce(<<>>, fn n, acc -> <<acc::bits, n::11>> end)

    total_size = bit_size(data_and_checksum)
    data_size = div(total_size * 32, 33)
    checksum_size = total_size - data_size

    <<data::bits-size(data_size), partial_checksum::bits-size(checksum_size)>> =
      data_and_checksum

    if <<data::bits, partial_checksum::bits>> == attach_checksum(data) do
      {:ok, data}
    else
      {:error, :bad_checksum}
    end
  end

  defp generate_entropy do
    :crypto.rand_uniform(16, 32 + 1)
    |> :crypto.strong_rand_bytes()
  end

  defp attach_checksum(entropy) do
    hash = :crypto.hash(:sha256, entropy)

    size =
      entropy
      |> bit_size
      |> div(32)

    <<checksum::bits-size(size), _::bits>> = hash

    <<entropy::bits, checksum::bits>>
  end

  defp map_onto_wordlist(entropy) do
    for <<chunk::11 <- entropy>> do
      Enum.at(@wordlist, chunk)
    end
  end
end
