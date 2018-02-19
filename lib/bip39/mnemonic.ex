defmodule Bip39.Mnemonic do
  def generate do
    entropy
    |> attach_checksum
    |> map_onto_wordlist
  end

  defp entropy do
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
    wordlist =
      Application.fetch_env!(
        :bip39,
        :wordlist
      )

    for <<chunk::11 <- entropy>> do
      Enum.at(wordlist, chunk)
    end
  end
end
