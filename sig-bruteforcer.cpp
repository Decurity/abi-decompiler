/*
 * Multi-threaded EVM function signature bruteforcer
 * Omar @beched Ganiev, Decurity.io
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "sha3.h"
#include <sstream>
#include <string>
#include <thread>
#include <vector>

int MAX_VAR_COUNT = 3;
int THREADS_NUM = 4;
std::vector<std::string> dict;

std::string uint8_to_hex_string(const uint8_t *v, const size_t s) {
    std::stringstream ss;

    ss << std::hex << std::setfill('0');

    for (int i = 0; i < s; i++) {
        ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
    }

    return ss.str();
}

std::string unhex(const std::string string) {
    std::string res;

    for (size_t i = 0; i < string.length(); i += 2) {
        const std::string hex = string.substr(i, 2);
        char decimal = std::strtol(hex.c_str(), 0, 16);
        res.push_back(decimal);
    }

    return res;
}

void combinations(std::vector<std::string> &s, std::vector<int> &pos, int n, int repeat, std::string func, std::vector<std::string> &res) {
    if (n == std::min((int) s.size(), repeat)) {
        std::string comb = func + "(";
        comb += s[pos[0]];
        for (int i = 1; i != n; ++i) {
            comb += "," + s[pos[i]];
        }
        res.push_back(comb + ")");
        return;
    }
    for (int i = 0; i != s.size(); ++i) {
        pos[n] = i;
        combinations(s, pos, n + 1, repeat, func, res);
    }
}

void doit(int from, int to, std::string sig) {
    std::cout << "Started thread from: " << from << std::endl;
    
    std::vector<std::string> argtypes = {"bytes8", "bytes16", "bytes32", "uint256", "int256"};
    std::vector<uint8_t> sig_vec(sig.begin(), sig.end());

    for(int pos = from; pos < to; ++pos) {
        std::string func = dict[pos];
        std::vector<std::string> candidates;

        for(int var_count = 1; var_count < std::min(MAX_VAR_COUNT, (int) argtypes.size()); ++var_count) {
            std::vector<int> pos(argtypes.size(), 0);
            combinations(argtypes, pos, 0, var_count, func, candidates);

            /*std::vector<std::string> args(MAX_VAR_COUNT);
            for(int var_num = 0; var_num < var_count; ++var_num) {

            }*/
            
            
            /*std::sort(argtypes.begin(), argtypes.end());

            do {
                std::ostringstream args;
                std::copy(
                    argtypes.begin(),
                    argtypes.begin() + var_count,
                    std::ostream_iterator<std::string>(args, ",")
                );
                std::string res = args.str();
                candidates.push_back(func + "(" + res.substr(0, res.length() - 1) + ")");
            } while(std::next_permutation(argtypes.begin(), argtypes.end()));*/
        }

        for(std::string &candidate: candidates) {
            uint8_t hash[64];
            sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, candidate.c_str(), candidate.length(), hash, 64);
            //std::cout << candidate << " => " << uint8_to_hex_string(hash, 4) << std::endl;
            std::vector<uint8_t> hash_vec(std::begin(hash), std::end(hash));
            if(std::equal(sig_vec.begin(), sig_vec.end(), hash_vec.begin())) {
                std::cout << "FOUND => " << candidate << std::endl;
                exit(0);
            }
        }
    
    }
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        std::cout << "Usage: ./sig-bruteforcer <signature> <path/to/dict> <threads> <max vars>" << std::endl;
        return 0;
    }
    if(argc > 3) {
        THREADS_NUM = std::stoi(argv[3]);
        if(argc > 4) {
            MAX_VAR_COUNT = std::stoi(argv[4]);
        }
    }

    std::string sig = unhex(argv[1]);
    std::vector<std::thread> threads;

    std::ifstream is(argv[2]);
    std::string line;
    while(getline(is, line))
    {
        dict.push_back(line);
    }

    int chunk_size = dict.size() / THREADS_NUM;

    for(int i = 0; i < dict.size(); i += chunk_size) {
        threads.push_back(std::thread(doit, i, std::max(i + chunk_size, (int) dict.size()), sig));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    for(auto &t: threads) {
        t.join();
    }

    return 0;
}
