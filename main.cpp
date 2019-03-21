// TODO some license header and copyright.
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

#include <cassert>
#include <cstring>
#include <cstdio>

// Include headers for SHA1 algorithm implemented in OpenSSL crypto's library.
#include <openssl/sha.h>

// if set to non-zero value, compiles and runs the long version of the program.
// It is capable of cracking three words combinations as well, but it can take several hours to finish.
#define LONG_RUN 0

// Number of hashes to be cracked.
#define NHASHES 20

// the longest word in the dictionary has 16 symbols.
#define MAX_WORDS_SIZE 20

// the real number of words in the dictionary we are given is 5579
#define NWORDS 5579

// We assume that noone wants to input long-long passwords anytime.
#define MAX_PASSWORD_SIZE  18

// The other number conceptions is explained in the technical report.
// Basically, it is an arbitrary number, remembered well by the user, i.e. a date.
#define OTHER_NUMBER_LIMIT 1000000
using namespace std;

// Function that converts a hexadecimal number in interval [0; 15]
// into an ascii character corresponding to it.
char hex_to_character(int num) {
    static char hex_to_char_map[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    return hex_to_char_map[num];
}

// Converts digit character into decimal number. 
static int character_to_hex(char c) {
    assert((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'));
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return c - '0';
    }
}

static string hash_to_string(unsigned char hash[SHA_DIGEST_LENGTH]) {
    string res;
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
        unsigned char c = hash[i];
        res += hex_to_character(c >> 4);
        res += hex_to_character(c & 0xF);
    }
    return res;
}

// List of loaded hashes to search for.
unsigned char hashes[NHASHES][SHA_DIGEST_LENGTH];
bool hash_is_found[NHASHES];

// We space for three words to be in it.
// string_to_check is a buffer used for check_hash() function
// in order to provide byte sequence into OpenSSL procedures.
unsigned char string_to_check[MAX_WORDS_SIZE * 3];

// SHA1 digest is stored here.
static unsigned char hash_result[SHA_DIGEST_LENGTH];

// Calculate hash on current state of string_to_check and all the hashes not found yet.
// inline optimization - trying to minimize call/return payload.
inline void check_hash() {
    for (int i = 0; i < NHASHES; ++i) {
        if (hash_is_found[i]) {
            continue;
        }

        if (memcmp(hash_result, hashes[i], SHA_DIGEST_LENGTH) == 0) {
            hash_is_found[i] = true;
            auto current_hash = hash_to_string(hash_result);
            cerr << int(i + 1) << " " << current_hash << " " << string_to_check << endl;
        }
    }
}

// Function for simple hash checking, without any optimization and takes a string as an argument.
void simple_check_hash(const string &s) {
	// Copying first number string into a char buffer used for comparison.
	memset(string_to_check, 0, sizeof(string_to_check));
	memcpy(string_to_check, s.c_str(), s.size());

	// Running SHA1 and get digest into hash_result array.
	SHA1(string_to_check, s.size(), hash_result);

	// Check the current hash, if has any hit in our input set of hashes, report.
	check_hash();
}

// Structure for one dictionary item.
struct WordStructure {
    char buf[MAX_WORDS_SIZE];
    unsigned int len;
};

// The whole dictionary data.
static WordStructure words[NWORDS];

// Load the dictionary from the path specified.
void load_dictionary(const string &dict_path) {
    FILE* f = fopen(dict_path.c_str(), "r");
    assert(f != NULL);
    for (int i = 0; i < NWORDS; ++i) {
        fscanf(f, "%s\n", words[i].buf);
        words[i].len = strlen(words[i].buf);
    }
    fclose(f);
}

// Function which reads SHA1 digests for encrypted passwords
// from the filepath specified as an argument.
vector<string> get_hashes(const string &hashes_path) {
    ifstream fin_pswd{hashes_path};
    assert(fin_pswd.is_open());
    vector<string> all_hashes;
    for (size_t i = 0; i < 20; i++) {
        size_t num;
        fin_pswd >> num;
        assert(num - 1 == i);
        string s;
        fin_pswd >> s;
        all_hashes.push_back(s);
    }
    return all_hashes;
}

// Return a vector of numbers considered to be easily remembered,
// so pretty often used by a incautious person.
vector<string> get_simple_numbers() {
    // There are a range of widespread easy-to-remember numbers.
    // For example, 0000, 1234, 111111, etc.
    // We store them all (or the ones we remembered) into
    // simple_numbers_set.

    set<string> simple_numbers_set;
    simple_numbers_set.insert("911");
    simple_numbers_set.insert("451");
    simple_numbers_set.insert("007");
	simple_numbers_set.insert("777");

    string natural_order, reverse_natural_order, zeroes;
    // Generate natural ordering numbers strings and all-zeroes strings.
    for (int i = 1; i <= 9; ++i) {
    	const auto istr = std::to_string(i);
        natural_order += static_cast<char>('0' + i);
        simple_numbers_set.insert(natural_order);

	    reverse_natural_order = istr + reverse_natural_order;
	    simple_numbers_set.insert(reverse_natural_order);

        zeroes += '0';
        simple_numbers_set.insert(zeroes);
    }

    simple_numbers_set.insert("1234567890");
	simple_numbers_set.insert("9876543210");

	// Some small numbers (may be age).
	for (int i = 1; i < 50; ++i) {
		auto istr = to_string(i);
		simple_numbers_set.insert(istr);
	}

    return vector<string>(simple_numbers_set.begin(), simple_numbers_set.end());
}

// As command line argument, it receives.
int main(int argc, char **argv) {
	if (argc != 3) {
		cerr << "USAGE:\n\t" << argv[0] << " <idx_proc: 0..nprocs-1> <nprocs>" << endl;
		cerr << "where:\n\tidx_proc - this process' index in the pool" << endl;
		cerr << "\t<nprocs> - the number of processes in the pool" << endl;
		return 1;
	}
	// For multi-processor environment
	// we specify the number of processes created by xargs to perform the task

	const int idx_proc = atoi(argv[1]);
	const int nprocs = atoi(argv[2]);
	assert(idx_proc >= 0 && nprocs > 0 && idx_proc < nprocs);

    load_dictionary("dictionary.txt");
    auto all_hashes = get_hashes("passwords.txt");

    // As we our hash arrays have array size of NHASHES,
    // we have to make sure the size of all_hashes are equal to it.
    assert(NHASHES == all_hashes.size());

    // Convert strings from all_hashes vector to C array
    // for faster passing into crypto's SHA1 function.
    for (size_t i = 0; i < NHASHES; i++) {
        assert(all_hashes[i].size() == 2 * SHA_DIGEST_LENGTH);

        // Iterating SHA1 hash's every byte which is composed of two letters -
        // hexadecimal digits: 0123456789abcdef
        for (size_t j = 0; j < SHA_DIGEST_LENGTH; j++) {
            char c;

            // First character is the is bigger order half-byte in
            // current byte, that is why we multiply it by hexadecimal base - 16.
            c = all_hashes[i][2 * j];
            hashes[i][j] += static_cast<unsigned char>(character_to_hex(c) * 16);

            // Second character is lower half-byte.
            c = all_hashes[i][2 * j + 1];
            hashes[i][j] += static_cast<unsigned char>(character_to_hex(c));
        }
    }

    auto simple_numbers = get_simple_numbers();

    // Running hash check on simple numbers.
	for (int i = idx_proc; i < simple_numbers.size(); i += nprocs) {
		simple_check_hash(simple_numbers[i]);
	}

    for (int i = idx_proc; i < NWORDS; i += nprocs) {
    	// This string visualized very well how fast the program is going.
//        cout << "it=" << i << endl;

		// Aliases for w1 fields.
        const char *w1 = words[i].buf;
        const unsigned int w1size = words[i].len;
        string w1string = w1;
	    simple_check_hash(w1string);

        // Trying to combine a word from dictionary with a simple number.
        for (auto const &num_str : simple_numbers) {
	        // Concatenate a word and a simple number.
            // We assume a simple number string can only appear in a password after a word part.
            simple_check_hash(w1string + num_str);
        }

        for (int j = 0; j < NWORDS; ++j) {
            const char *w2 = words[j].buf;
            const unsigned int w2size = words[j].len;
            const unsigned int w1w2size = w1size + w2size;

            // Skipping sequences too long to be a password.
            if (w1w2size > MAX_PASSWORD_SIZE) {
                continue;
            }

            memcpy(string_to_check, w1, w1size);
            memcpy(string_to_check + w1size, w2, w2size);

            // Setting null terminator for the string,
            // so it will be written into stdout correctly if hash is a match.
            string_to_check[w1w2size] = '\0';

            // Running hashing process.
            SHA1(string_to_check, w1w2size, hash_result);
            // Check if hash is one of we are looking for.
            check_hash();

            for (auto const &num_str : simple_numbers) {
                const unsigned int num_str_len = num_str.size();
                const unsigned int w1w2numsize = w1w2size + num_str_len;

                // Skipping sequences too long to be a password.
                if (w1w2numsize > MAX_PASSWORD_SIZE) {
                    continue;
                }

                // Concatenate two words and a simple number.
                memcpy(string_to_check + w1w2size, num_str.c_str(), num_str_len);
	            // Setting null terminator for the string,
	            // so it will be written into stdout correctly if hash is a match.
                string_to_check[w1w2numsize] = '\0';
                SHA1(string_to_check, w1w2numsize, hash_result);
                check_hash();
            }
#if LONG_RUN
            // Precalculate SHA1 for w1 and w2 concatenation.
            SHA_CTX ctx, saved_ctx;
            SHA1_Init(&saved_ctx);
            SHA1_Update(&saved_ctx, string_to_check, w1w2size);

            for (int k = 0; k < NWORDS; ++k) {
                const char *w3 = words[k].buf;
                const int w3size = words[k].len;
                const int w1w2w3size = w1w2size + w3size;

                if (w1w2w3size > MAX_PASSWORD_SIZE) {
                    continue;
                }

                // Copy precalculated context for SHA1.
                memcpy(&ctx, &saved_ctx, sizeof(SHA_CTX));

                // Calculate and finalize SHA1
                SHA1_Update(&ctx, w3, w3size);
                SHA1_Final(hash_result, &ctx);
                check_hash();
            }
#endif
        }
    }

	for (int num = idx_proc; num < OTHER_NUMBER_LIMIT; num += nprocs) {
		const string num_str = std::to_string(num);

		if (!binary_search(simple_numbers.begin(), simple_numbers.end(), num_str)) {
			// Check hash for this number if it hasn't already been checked as a simple number.
			simple_check_hash(num_str);
		}

		for (auto const &simple_num_str : simple_numbers) {
			// Assuming the case when an arbitrary number goes in password before somple simple one.
			simple_check_hash(num_str + simple_num_str);

			// Now checking the cases when a simple number goes before usual one.
			simple_check_hash(simple_num_str + num_str);
		}
	}

    return 0;
}
