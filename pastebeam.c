#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#define PORT 6969
#define ADDRESS "45.146.253.5"

size_t base64_encode(const unsigned char *data, unsigned char *output_buffer, size_t input_length) {
    static const char encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
    };

    static const int mod_table[] = {0, 2, 1};

    size_t output_length = 4 * ((input_length + 2) / 3);

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output_buffer[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        output_buffer[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        output_buffer[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        output_buffer[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        output_buffer[output_length - 1 - i] = '=';

    return output_length;
}

static unsigned long long fast_rand_seed;

void fast_srand(unsigned int seed) {
    fast_rand_seed = seed;
}

int fast_rand() {
    fast_rand_seed = (214013*fast_rand_seed+2531011);
    return (fast_rand_seed>>32)&RAND_MAX;
}

void print_help(void) {
    printf(
        "pastebeam <command> [argument]\n"
        "\n"
        "  get <id>        - get a pastebin from its id\n"
        "  post <filename> - post a file and print its id\n"
    );
}

#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

#define SHA256_DIGEST_LENGTH 32

typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned int bitlen[2];
	unsigned int state[8];
} SHA256_CTX;

static const unsigned int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX *ctx, unsigned char data[]) {
	unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX *ctx) {
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX *ctx, unsigned char data[], size_t len) {
	for (unsigned int i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			SHA256Transform(ctx, ctx->data);
			DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
			ctx->datalen = 0;
		}
	}
}

void SHA256Final(SHA256_CTX *ctx, unsigned char hash[]) {
	unsigned int i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		SHA256Transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	SHA256Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void SHA256(unsigned char* data, size_t data_size, unsigned char *output) {
	SHA256_CTX ctx;

	SHA256Init(&ctx);
	SHA256Update(&ctx, data, data_size);
	SHA256Final(&ctx, output);
}

void expect_response(int descriptor, const char *text) {
    char response_buffer[64] = {0};
    read(descriptor, response_buffer, 63);
    if (strcmp(response_buffer, text ) != 0) {
        fprintf(stderr, "Expected %s from server but got %s.\n", text, response_buffer);
        fprintf(stderr, "Server does not seem to be a pastebeam server.\n");
        exit(EXIT_FAILURE);
    }
}

typedef struct {
    char *data;
    ssize_t count;
} String_Slice;

#define MAX_SLICES 10

typedef struct {
    String_Slice slices[MAX_SLICES];
    ssize_t count;
} Fixed_String_Slice_Array;

Fixed_String_Slice_Array split_by_space(char *data) {
    Fixed_String_Slice_Array result = {0};

    char *last_chunk = data;
    for (char *i = data; *i != '\0'; i += 1) {
        if (*i == ' ') {
            assert(result.count != MAX_SLICES - 1);

            result.slices[result.count++] = (String_Slice) {
                .data  = last_chunk,
                .count = i - last_chunk
            };

            last_chunk = i + 1;
        }
    }

    result.slices[result.count++] = (String_Slice) {
        .data  = last_chunk,
        .count = strlen(last_chunk)
    };

    return result;
}

int main(int argc, char **argv) {

    switch (argc) {
        case 3: break;
        default:
            fprintf(stderr, "Wrong number of arguments provided. Expected 2.\n");
            print_help();
            exit(EXIT_FAILURE);
    }

    enum { GET, POST } action;

    if (strcmp(argv[1], "get") == 0) {
        action = GET;
    } else if (strcmp(argv[1], "post") == 0) {
        action = POST;
    } else {
        fprintf(stderr, "Unrecognized command %s", argv[1]);
        print_help();
        exit(EXIT_FAILURE);
    }

    int socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_descriptor < 0) {
        fprintf(stderr, "Failed to open socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address = {0};
    server_address.sin_family         = AF_INET;
    server_address.sin_port           = htons(PORT);

    if (inet_pton(AF_INET, ADDRESS, &server_address.sin_addr) <= 0) {
        fprintf(stderr, "Failed to parse address %s: %s", ADDRESS, strerror(errno));
        exit(EXIT_FAILURE);
    }

    int connect_status = connect(
        socket_descriptor,
        (struct sockaddr*) &server_address,
        sizeof(server_address)
    );

    if (connect_status < 0) {
        fprintf(stderr, "Failed to connect to server %s:%d: %s", ADDRESS, PORT, strerror(errno));
        exit(EXIT_FAILURE);
    }

    expect_response(socket_descriptor, "HI\r\n");

    switch (action) {
    case GET: {

        #define BUFFER_SIZE 4096
        static char buffer[BUFFER_SIZE] = {0};

        char message[BUFFER_SIZE] = {0};
        snprintf(message, BUFFER_SIZE, "GET %s\r\n", argv[2]);

        send(socket_descriptor, message, strlen(message), 0);

read_again:
        switch(read(socket_descriptor, buffer, BUFFER_SIZE - 1)) {
            case 0:
                break;
            case -1:
                fprintf(stderr, "read returned error: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            default:
            printf("%s", buffer);
            memset(buffer, 0, BUFFER_SIZE);
            goto read_again;
        }

        close(socket_descriptor);

        #undef BUFFER_SIZE

    } break;
    case POST: {
        static const char *post_message = "POST\r\n";
        send(socket_descriptor, post_message, strlen(post_message), 0);

        expect_response(socket_descriptor, "OK\r\n");

        int file_descriptor = open(argv[2], O_RDONLY);

        if (file_descriptor < 0) {
            fprintf(stderr, "Failed to open file %s: %s\n", argv[2], strerror(errno));
            exit(EXIT_FAILURE);
        }

        struct stat file_stats = {0};
        if (fstat(file_descriptor, &file_stats) < 0) {
            fprintf(stderr, "Failed to determine file size of file %s: %s", argv[2], strerror(errno));
            exit(EXIT_FAILURE);
        }

        size_t file_data_cursor = 0;
        char *file_data         = calloc(file_stats.st_size * 2, 1); // if the file is all new lines, the size will double

        // \n --> \r\n conversion
        {
            #define push(string)                               \
                do {                                           \
                    send(socket_descriptor, (string), 1, 0);   \
                    file_data[file_data_cursor++] = *(string); \
                } while (0)

            ssize_t bytes_read = 0;
            char line_buffer[1024] = {0};

            while ((bytes_read = read(file_descriptor, line_buffer, sizeof(line_buffer))) > 0) {
                for (ssize_t i = 0; i < bytes_read; i++) {
                    if (line_buffer[i] == '\n')
                        push("\r");

                    push(&line_buffer[i]);

                    // This should not be needed in the future hopefully
                    if (line_buffer[i] == '\n')
                        expect_response(socket_descriptor, "OK\r\n");
                }
            }

            #undef push
        }

        size_t file_data_size = strlen(file_data);

        static const char *end_message = "SUBMIT\r\n";
        send(socket_descriptor, end_message, strlen(end_message), 0);


        char challenge_buffer[4096] = {0};
        read(socket_descriptor, challenge_buffer, 4096 - 1);

        // CHALLENGE sha256 5 BDN02GeEB5JHEQ9b6z4plyfpqErurlc3rqIf8pV8pQA=

        Fixed_String_Slice_Array list = split_by_space(challenge_buffer);

        if (list.count != 4) {
            fprintf(stderr, "Got bogus response from the server: %s\n", challenge_buffer);
            exit(EXIT_FAILURE);
        }

        assert(strncmp(list.slices[0].data, "CHALLENGE", strlen("CHALLENGE")) == 0);
        assert(strncmp(list.slices[1].data, "sha256",    strlen("sha256"))    == 0);
        assert(strncmp(list.slices[2].data, "6",         strlen("6"))         == 0);

        struct timespec timestamp;
        clock_gettime(CLOCK_MONOTONIC_RAW, &timestamp);

        fast_srand(timestamp.tv_sec);

        bool success = false;

        unsigned char *arena            = calloc(1024*1024, 1);
        unsigned char random_bytes[100] = {0};
        while (!success) {
            int amount_of_characters = (fast_rand() % 97) + 3;

            for (int i = 0; i < amount_of_characters; i++) {
                random_bytes[i] = fast_rand() % 255;
            }


            unsigned char *arena_cursor = arena;
            int prefix_count = base64_encode(random_bytes, arena, amount_of_characters);
            arena_cursor += prefix_count;

            *(arena_cursor++) = '\r'; *(arena_cursor++) = '\n';

            memcpy(arena_cursor, file_data, file_data_size);
            arena_cursor += file_data_size;

            // TODO: if files dont end with a newline, it will need to be added here
            // However, files should end with a newline on UNIX, otherwise you are
            // gay.
            //
            // *(arena_cursor++) = '\r'; *(arena_cursor++) = '\n';

            memcpy(arena_cursor, list.slices[3].data, list.slices[3].count);
            arena_cursor += list.slices[3].count;

            size_t combined_size = arena_cursor - arena;

            unsigned char sha_hash[SHA256_DIGEST_LENGTH];

            SHA256(arena, combined_size, sha_hash);

            int zero_counter = 0;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                if (sha_hash[i] == 0x00) {
                    zero_counter += 2;
                } else if (sha_hash[i] < 0x10) {
                    zero_counter += 1;
                    break;
                } else {
                    break;
                }
            }

            // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            //     printf("%02x", sha_hash[i]);
            // printf("\n");

            if (zero_counter >= 6) {
                char response_buffer[4096] = {0};
                int response_size = snprintf(response_buffer, 4096, "ACCEPTED %.*s\r\n", prefix_count, arena);

                send(socket_descriptor, response_buffer, response_size, 0);

                memset(response_buffer, 0, 4096);
                read(socket_descriptor, response_buffer, 4096);

                puts(response_buffer);

                success = true;
            }
        }


        close(socket_descriptor);
    } break;
    }

    return 0;
}
