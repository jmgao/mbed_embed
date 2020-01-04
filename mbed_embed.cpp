#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#define PRINT_FIELD(var_name, x, name, ...) emit_field(var_name, #name, x.name, __VA_ARGS__)
#define PRINT_FIELD_PTR(var_name, x, name, ...) emit_field(var_name, #name, x->name, __VA_ARGS__)

static int indentation;
struct scoped_indent {
  scoped_indent() { ++indentation; }
  ~scoped_indent() { --indentation; }
};

static void indent(FILE* fp) {
  for (int i = 0; i < indentation; ++i) {
    fprintf(fp, "  ");
  }
}

static void emit_field(const char*, const char* field_name, int value, FILE* f = stdout) {
  indent(f);
  fprintf(f, ".%s = %d,\n", field_name, value);
}

static void emit_field(const char*, const char* field_name, size_t value, FILE* f = stdout) {
  indent(f);
  fprintf(f, ".%s = %zu,\n", field_name, value);
}

static void emit_field(const char* var_name, const char* field_name, mbedtls_mpi& value, FILE* f, FILE* limbs) {
  indent(f);
  fprintf(f, ".%s = {\n", field_name);

  {
    scoped_indent _;
    PRINT_FIELD(var_name, value, s, f);
    PRINT_FIELD(var_name, value, n, f);
    indent(f);
    if (value.p) {
      fprintf(f, ".p = const_cast<mbedtls_mpi_uint*>(__limbs_%s_%s),\n", var_name, field_name);
      fprintf(limbs, "static const mbedtls_mpi_uint __limbs_%s_%s[%zu] = {\n", var_name, field_name, value.n);
      fprintf(limbs, "  ");
      for (size_t i = 0; i < value.n; ++i) {
        fprintf(limbs, "%lu, ", static_cast<unsigned long>(value.p[i]));
      }
      fprintf(limbs, "\n};\n");

    } else {
      fprintf(f, ".p = 0,\n");
    }
  }

  indent(f);
  fprintf(f, "},\n");
}

void emit_array(const char* name, const unsigned char* data, size_t len, FILE* f = stdout) {
  indent(f);
  fprintf(f, "const unsigned char %s[%zu] = {\n", name, len);
  {
    scoped_indent _;
    indent(f);
    for (size_t i = 0; i < len; ++i) {
      fprintf(f, "0x%02x, ", data[i]);
    }
  }
  fprintf(f, "\n};\n");
}

static void emit_mbedtls(mbedtls_rsa_context* rsa, const char* name, bool emit_ne) {
  char* struct_buf = nullptr;
  size_t struct_len = 0;

  char* limbs_buf = nullptr;
  size_t limbs_len = 0;

  FILE* f = open_memstream(&struct_buf, &struct_len);
  FILE* limbs = open_memstream(&limbs_buf, &limbs_len);

  fprintf(f, "const struct mbedtls_rsa_context __%s = {\n", name);
  {
    scoped_indent _;
    PRINT_FIELD_PTR(name, rsa, ver, f);
    PRINT_FIELD_PTR(name, rsa, len, f);
    PRINT_FIELD_PTR(name, rsa, N, f, limbs);
    PRINT_FIELD_PTR(name, rsa, E, f, limbs);

    PRINT_FIELD_PTR(name, rsa, D, f, limbs);
    PRINT_FIELD_PTR(name, rsa, P, f, limbs);
    PRINT_FIELD_PTR(name, rsa, Q, f, limbs);

    PRINT_FIELD_PTR(name, rsa, DP, f, limbs);
    PRINT_FIELD_PTR(name, rsa, DQ, f, limbs);
    PRINT_FIELD_PTR(name, rsa, QP, f, limbs);

    PRINT_FIELD_PTR(name, rsa, RN, f, limbs);

    PRINT_FIELD_PTR(name, rsa, RP, f, limbs);
    PRINT_FIELD_PTR(name, rsa, RQ, f, limbs);

    PRINT_FIELD_PTR(name, rsa, Vi, f, limbs);
    PRINT_FIELD_PTR(name, rsa, Vf, f, limbs);

    indent(f);
    fprintf(f, ".padding = MBEDTLS_RSA_PKCS_V21,\n");

    indent(f);
    fprintf(f, ".hash_id = MBEDTLS_MD_SHA256,\n");
  }

  fprintf(f, "};\n");
  fprintf(f, "\n");

  fclose(f);
  fclose(limbs);

  printf("%s\n%s", limbs_buf, struct_buf);

  if (emit_ne) {
    char key_n_name[256];
    if (snprintf(key_n_name, 256, "%s_n", name) >= 256) {
      errx(1, "variable name overflow: %s_n", name);
    }

    unsigned char key_n[256];
    if (mbedtls_mpi_write_binary(&rsa->N, key_n, sizeof(key_n)) != 0) {
      errx(1, "failed to write key_n as big endian");
    }

    char key_e_name[256];
    if (snprintf(key_e_name, 256, "%s_n", name) >= 256) {
      errx(1, "variable name overflow: %s_n", name);
    }

    unsigned char key_e[256];
    if (mbedtls_mpi_write_binary(&rsa->E, key_e, sizeof(key_e)) != 0) {
      errx(1, "failed to write key_e as big endian");
    }

    emit_array(key_n_name, key_n, sizeof(key_n));
    emit_array(key_e_name, key_e, sizeof(key_e));
  }
}

void usage(int rc) {
  fprintf(stderr,
          "usage: mbed_embed [-r RSA_KEY_FILE VARIABLE_NAME]...\n"
          "                  [-f FILE VARIABLE_NAME]...\n");
  exit(rc);
}

struct EmbedRSA {
  std::string variable_name;
  std::string path;
};

struct EmbedBinary {
  std::string variable_name;
  std::string path;
};

using Action = std::variant<EmbedRSA, EmbedBinary>;

static void embed_rsa(const char* path, const char* name) {
  unsigned char der_buf[4096];
  size_t der_len;
  {
    FILE* f = fopen(path, "r");
    if (!f) {
      err(1, "failed to open '%s'", path);
    }

    der_len = fread(der_buf, 1, sizeof(der_buf), f);
    if (der_len == 0) {
      errx(1, "failed to read from '%s'", path);
    }

    fclose(f);
  }

  mbedtls_pk_context pk_ctx;
  mbedtls_pk_init(&pk_ctx);

  int rc = mbedtls_pk_parse_key(&pk_ctx, der_buf, der_len, nullptr, 0);
  if (rc != 0) {
    errx(1, "failed to parse key");
  }

  if (mbedtls_pk_get_type(&pk_ctx) != MBEDTLS_PK_RSA) {
    errx(1, "invalid key format");
  }

  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk_ctx);
  if (mbedtls_rsa_complete(rsa) != 0) {
    errx(1, "failed to complete RSA key");
  }

  // Populate RN.
  mbedtls_mpi temp;
  mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&rsa->RN);
  if (mbedtls_mpi_exp_mod(&temp, &rsa->E, &rsa->E, &rsa->N, &rsa->RN) != 0) {
    errx(1, "failed to populate RN");
  }

  emit_mbedtls(rsa, name, true);
}

static void embed_binary(const char* path, const char* name) {
  struct stat st;
  if (stat(path, &st) != 0) {
    err(1, "failed to stat '%s'", path);
  }

  std::unique_ptr<unsigned char[]> buf = std::make_unique<unsigned char[]>(st.st_size);
  if (!buf) {
    errx(1, "failed to allocate %" PRId64 " byte buffer for '%s'", static_cast<int64_t>(st.st_size), path);
  }

  size_t file_len = 0;
  {
    FILE* f = fopen(path, "r");
    if (!f) {
      err(1, "failed to open '%s'", path);
    }

    file_len = fread(buf.get(), 1, st.st_size, f);
    if (file_len == 0) {
      errx(1, "failed to read from '%s'", path);
    }

    fclose(f);
  }

  emit_array(name, buf.get(), file_len);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(1);
  }

  --argc;
  ++argv;

  std::vector<Action> actions;
  while (argc > 0) {
    if (strcmp("-r", argv[0]) == 0) {
      if (argc < 3) {
        usage(1);
      }

      actions.emplace_back(EmbedRSA{
          .variable_name = argv[2],
          .path = argv[1],
      });

      argc -= 3;
      argv += 3;
    } else if (strcmp("-f", argv[0]) == 0) {
      if (argc < 3) {
        usage(1);
      }

      actions.emplace_back(EmbedBinary{
          .variable_name = argv[2],
          .path = argv[1],
      });

      argc -= 3;
      argv += 3;
    } else {
      usage(1);
    }
  }

  printf("#include <mbedtls/rsa.h>\n");
  printf("\n");

  // Emit static_assert to enforce that the target's 64-bitness matches that of ours.
  // TODO: Emit both 32 and 64 bit version of the limbs with an ifdef.
  printf(
      "static_assert(sizeof(mbedtls_mpi_uint) == %d, "
      "\"sizeof(mbedtls_mpi_uint) mismatch between target and mbed_embed\");",
      sizeof(mbedtls_mpi_uint));

  printf("\n");

  printf("#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__\n");
  printf("#error non-little endian not supported.\n");
  printf("#endif\n");

  printf("\n");

  for (const auto& action : actions) {
    if (auto rsa = std::get_if<EmbedRSA>(&action)) {
      embed_rsa(rsa->path.c_str(), rsa->variable_name.c_str());
    } else if (auto binary = std::get_if<EmbedBinary>(&action)) {
      embed_binary(binary->path.c_str(), binary->variable_name.c_str());
    }
  }
}
