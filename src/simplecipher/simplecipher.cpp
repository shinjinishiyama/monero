// Copyright (c) 2014-2017, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "cryptonote_basic/cryptonote_basic.h"
#include "common/base58.h"
#include "common/command_line.h"
#include "common/password.h"
#include "common/util.h"
#include "file_io_utils.h"
#include "version.h"

namespace po = boost::program_options;

std::string encrypt(const std::string &plaintext, const std::string &password)
{
  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password.data(), password.size(), key);
  std::string ciphertext;
  crypto::chacha8_iv iv = crypto::rand<crypto::chacha8_iv>();
  ciphertext.resize(plaintext.size() + sizeof(iv));
  crypto::chacha8(plaintext.data(), plaintext.size(), key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  return ciphertext;
}

std::string decrypt(const std::string &ciphertext, const std::string &password)
{
  const size_t prefix_size = sizeof(chacha8_iv);
  if (ciphertext.size() < prefix_size)
  {
    throw std::runtime_error("unexpected ciphertext size");
  }
  crypto::chacha8_key key;
  crypto::generate_chacha8_key(password.data(), password.size(), key);
  const crypto::chacha8_iv &iv = *(const crypto::chacha8_iv*)&ciphertext[0];
  std::string plaintext;
  plaintext.resize(ciphertext.size() - prefix_size);
  crypto::chacha8(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, &plaintext[0]);
  return plaintext;
}

int main(int argc, char* argv[])
{
  tools::sanitize_locale();

  po::options_description desc_cmd("Command line options");
  const command_line::arg_descriptor<bool> arg_encrypt  = {"encrypt", "", false};
  const command_line::arg_descriptor<bool> arg_decrypt  = {"decrypt", "", false};
  const command_line::arg_descriptor<std::string, true> arg_input_file = {"input-file", ""};
  const command_line::arg_descriptor<std::string, true> arg_output_file = {"output-file", ""};

  command_line::add_arg(desc_cmd, arg_encrypt);
  command_line::add_arg(desc_cmd, arg_decrypt);
  command_line::add_arg(desc_cmd, arg_input_file);
  command_line::add_arg(desc_cmd, arg_output_file);
  command_line::add_arg(desc_cmd, command_line::arg_help);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_cmd, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_cmd), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_cmd << std::endl;
    return 1;
  }

  bool encrypt = command_line::get_arg(vm, arg_encrypt);
  bool decrypt = command_line::get_arg(vm, arg_decrypt);
  if (!encrypt && !decrypt)
  {
    std::cerr << "Either --encrypt or --decrypt must be specified" << std::endl;
    return 1;
  }

  std::string input_file = command_line::get_arg(vm, arg_input_file);
  std::string output_file = command_line::get_arg(vm, arg_output_file);

  auto pwd_container = tools::password_container::prompt(false);
  if (!pwd_container)
  {
    std::cerr << "failed to read password" << std::endl;
    return 1;
  }

  if (encrypt){
    std::string plaintext;
    if (!epee::file_io_utils::load_file_to_string(input_file, plaintext))
    {
      std::cerr << "failed to read input file" << std::endl;
      return 1;
    }
    std::string ciphertext = ::encrypt(plaintext, pwd_container->password());
    std::string encoded = tools::base58::encode(ciphertext);

    // make new line every 64 characters
    int count = 0;
    auto iter = encoded.begin();
    while (iter != encoded.end())
    {
      if ((count + 1) % 65 == 0)
      {
        iter = encoded.insert(iter, '\n') + 1;
      }
      else
      {
        ++iter;
      }
      ++count;
    }
    encoded += '\n';

    if (!epee::file_io_utils::save_string_to_file(output_file, encoded))
    {
      std::cerr << "failed to write output file" << std::endl;
      return 1;
    }
  }
  else
  {
    std::string encoded;
    if (!epee::file_io_utils::load_file_to_string(input_file, encoded))
    {
      std::cerr << "failed to read input file" << std::endl;
      return 1;
    }

    // erase all new lines
    for (auto iter = encoded.begin(); iter != encoded.end(); )
    {
      if (*iter == '\n')
      {
        iter = encoded.erase(iter);
      }
      else
      {
        ++iter;
      }
    }

    std::string ciphertext;
    if (!tools::base58::decode(encoded, ciphertext))
    {
      std::cerr << "failed to decode with base58" << std::endl;
      return 1;
    }
    try
    {
      std::string plaintext = ::decrypt(ciphertext, pwd_container->password());
      if (!epee::file_io_utils::save_string_to_file(output_file, plaintext))
      {
        std::cerr << "failed to write output file" << std::endl;
        return 1;
      }
    }
    catch (const std::runtime_error& e)
    {
      std::cerr << e.what() << std::endl;
      return 1;
    }
  }
}
