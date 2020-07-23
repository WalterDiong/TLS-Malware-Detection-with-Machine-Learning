import json
import os
import socket
import pandas
import csv

# Paths to files and directories for benign and malicious jsons, and urls of top 1 million most visited sites
file = pandas.read_csv("location of csv of websits with benign urls")
benign_url_file = pandas.read_csv("Location of csv with benign urls")
benign_path = "path to benign files"
malicious_path = "Path to malicious files"
benign_files_directory = os.listdir(benign_path)
malicious_files_directory = os.listdir(malicious_path)

# Dictionaries of top 1 million visited sites in the world, cuphersuites, supported groups, and extensions
benign_urls = {}
supported_groups_dict = {}
ec_point_formats_dict = {}

cipher_suites_dict = {
"0000" : "TLS_NULL_WITH_NULL_NULL",
"0001" : "TLS_RSA_WITH_NULL_MD5",
"0002" : "TLS_RSA_WITH_NULL_SHA",
"0003" : "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
"0004" : "TLS_RSA_WITH_RC4_128_MD5",
"0005" : "TLS_RSA_WITH_RC4_128_SHA",
"0006" : "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
"0007" : "TLS_RSA_WITH_IDEA_CBC_SHA",
"0008" : "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
"0009" : "TLS_RSA_WITH_DES_CBC_SHA",
"000a" : "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
"000b" : "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
"000c" : "TLS_DH_DSS_WITH_DES_CBC_SHA",
"000d" : "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
"000e" : "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
"000f" : "TLS_DH_RSA_WITH_DES_CBC_SHA",
"0010" : "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
"0011" : "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
"0012" : "TLS_DHE_DSS_WITH_DES_CBC_SHA",
"0013" : "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
"0014" : "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
"0015" : "TLS_DHE_RSA_WITH_DES_CBC_SHA",
"0016" : "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
"0017" : "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
"0018" : "TLS_DH_anon_WITH_RC4_128_MD5",
"0019" : "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
"001A" : "TLS_DH_anon_WITH_DES_CBC_SHA",
"001B" : "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
"001E" : "TLS_KRB5_WITH_DES_CBC_SHA",
"001F" : "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
"0020" : "TLS_KRB5_WITH_RC4_128_SHA",
"0021" : "TLS_KRB5_WITH_IDEA_CBC_SHA",
"0022" : "TLS_KRB5_WITH_DES_CBC_MD5",
"0023" : "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
"0024" : "TLS_KRB5_WITH_RC4_128_MD5",
"0025" : "TLS_KRB5_WITH_IDEA_CBC_MD5",
"0026" : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
"0027" : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
"0028" : "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
"0029" : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
"002a" : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
"002b" : "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
"002c" : "TLS_PSK_WITH_NULL_SHA",
"002d" : "TLS_DHE_PSK_WITH_NULL_SHA",
"002e" : "TLS_RSA_PSK_WITH_NULL_SHA",
"002f" : "TLS_RSA_WITH_AES_128_CBC_SHA",
"0030" : "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
"0031" : "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
"0032" : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
"0033" : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
"0035" : "TLS_RSA_WITH_AES_256_CBC_SHA",
"0036" : "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
"0037" : "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
"0038" : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
"0039" : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
"003a" : "TLS_DH_anon_WITH_AES_256_CBC_SHA",
"003b" : "TLS_RSA_WITH_NULL_SHA256",
"003c" : "TLS_RSA_WITH_AES_128_CBC_SHA256",
"003d" : "TLS_RSA_WITH_AES_256_CBC_SHA256",
"003e" : "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
"003f" : "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
"0040" : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
"0041" : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
"0042" : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
"0043" : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
"0044" : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
"0045" : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
"0046" : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
"0067" : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
"0068" : "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
"0069" : "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
"006a" : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
"006b" : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
"006c" : "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
"006d" : "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
"0084" : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
"0085" : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
"0086" : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
"0087" : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
"0088" : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
"0089" : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
"008a" : "TLS_PSK_WITH_RC4_128_SHA",
"008b" : "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
"008c" : "TLS_PSK_WITH_AES_128_CBC_SHA",
"008d" : "TLS_PSK_WITH_AES_256_CBC_SHA",
"008e" : "TLS_DHE_PSK_WITH_RC4_128_SHA",
"008f" : "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
"0090" : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
"0091" : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
"0092" : "TLS_RSA_PSK_WITH_RC4_128_SHA",
"0093" : "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
"0094" : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
"0095" : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
"0096" : "TLS_RSA_WITH_SEED_CBC_SHA",
"0097" : "TLS_DH_DSS_WITH_SEED_CBC_SHA",
"0098" : "TLS_DH_RSA_WITH_SEED_CBC_SHA",
"0099" : "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
"009a" : "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
"009b" : "TLS_DH_anon_WITH_SEED_CBC_SHA",
"009c" : "TLS_RSA_WITH_AES_128_GCM_SHA256",
"009d" : "TLS_RSA_WITH_AES_256_GCM_SHA384",
"009e" : "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
"009f" : "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
"00a0" : "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
"00a1" : "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
"00a2" : "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
"00a3" : "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
"00a4" : "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
"00a5" : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"00a6" : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"00a7" : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"00a8" : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"00a9" : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"00aa" : "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
"00ab" : "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
"00ac" : "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
"00ad" : "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
"00ae" : "TLS_PSK_WITH_AES_128_CBC_SHA256",
"00af" : "TLS_PSK_WITH_AES_256_CBC_SHA384",
"00b0" : "TLS_PSK_WITH_NULL_SHA256",
"00b1" : "TLS_PSK_WITH_NULL_SHA384",
"00b2" : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
"00b3" : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
"00b4" : "TLS_DHE_PSK_WITH_NULL_SHA256",
"00b5" : "TLS_DHE_PSK_WITH_NULL_SHA384",
"00b6" : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
"00b7" : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
"00b8" : "TLS_RSA_PSK_WITH_NULL_SHA256",
"00b9" : "TLS_RSA_PSK_WITH_NULL_SHA384",
"00ba" : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"00bb" : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
"00bc" : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"00bd" : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
"00be" : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"00bf" : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
"00c0" : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"00c1" : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
"00c2" : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"00c3" : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
"00c4" : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"00c5" : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
"00c6" : "TLS_SM4_GCM_SM3",
"00c7" : "TLS_SM4_CCM_SM3",
"00ff" : "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
"1301" : "TLS_AES_128_GCM_SHA256",
"1302" : "TLS_AES_256_GCM_SHA384",
"1303" : "TLS_CHACHA20_POLY1305_SHA256",
"1304" : "TLS_AES_128_CCM_SHA256",
"1305" : "TLS_AES_128_CCM_8_SHA256",
"5600" : "TLS_FALLBACK_SCSV",
"c001" : "TLS_ECDH_ECDSA_WITH_NULL_SHA",
"c002" : "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
"c003" : "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
"c004" : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
"c005" : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
"c006" : "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
"c007" : "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
"c008" : "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
"c009" : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
"c00a" : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
"c00b" : "TLS_ECDH_RSA_WITH_NULL_SHA",
"c00c" : "TLS_ECDH_RSA_WITH_RC4_128_SHA",
"c00d" : "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
"c00e" : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
"c00f" : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
"c010" : "TLS_ECDHE_RSA_WITH_NULL_SHA",
"c011" : "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
"c012" : "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
"c013" : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
"c014" : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
"c015" : "TLS_ECDH_anon_WITH_NULL_SHA",
"c016" : "TLS_ECDH_anon_WITH_RC4_128_SHA",
"c017" : "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
"c018" : "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
"c019" : "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
"c01a" : "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
"c01b" : "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
"c01c" : "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
"c01d" : "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
"c01e" : "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
"c01f" : "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
"c020" : "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
"c021" : "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
"c022" : "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
"c023" : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
"c024" : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
"c025" : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
"c026" : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
"c027" : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
"c028" : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
"c029" : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
"c02a" : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
"c02b" : "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
"c02c" : "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
"c02d" : "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
"c02e" : "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
"c02f" : "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
"c030" : "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
"c031" : "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
"c032" : "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
"c033" : "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
"c034" : "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
"c035" : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
"c036" : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
"c037" : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
"c038" : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
"c039" : "TLS_ECDHE_PSK_WITH_NULL_SHA",
"c03a" : "TLS_ECDHE_PSK_WITH_NULL_SHA256",
"c03b" : "TLS_ECDHE_PSK_WITH_NULL_SHA384",
"c03c" : "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
"c03d" : "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
"c03e" : "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
"c03f" : "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
"c040" : "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
"c041" : "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
"c042" : "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
"c043" : "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
"c044" : "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
"c045" : "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
"c046" : "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
"c047" : "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
"c048" : "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
"c049" : "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
"c04a" : "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
"c04b" : "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
"c04c" : "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
"c04d" : "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
"c04e" : "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
"c04f" : "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
"c050" : "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
"c051" : "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
"c052" : "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
"c053" : "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
"c054" : "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
"c055" : "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
"c056" : "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
"c057" : "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
"c058" : "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
"c059" : "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
"c05a" : "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
"c05b" : "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
"c05c" : "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
"c05d" : "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
"c05e" : "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
"c05f" : "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
"c060" : "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
"c061" : "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
"c062" : "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
"c063" : "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
"c064" : "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
"c065" : "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
"c066" : "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
"c067" : "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
"c068" : "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
"c069" : "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
"c06a" : "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
"c06b" : "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
"c06c" : "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
"c06d" : "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
"c06e" : "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
"c06f" : "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
"c070" : "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
"c071" : "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
"c072" : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
"c073" : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
"c074" : "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
"c075" : "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
"c076" : "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"c077" : "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
"c078" : "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"c079" : "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
"c07a" : "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"c07b" : "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"c07c" : "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"c07d" : "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"c07e" : "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"c07f" : "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"c080" : "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
"c081" : "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
"c082" : "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
"c083" : "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
"c084" : "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
"c085" : "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
"c086" : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
"c087" : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
"c088" : "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
"c089" : "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
"c08a" : "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"c08b" : "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"c08c" : "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"c08d" : "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"c08e" : "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"c08f" : "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"c090" : "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"c091" : "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"c092" : "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"c093" : "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"c094" : "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"c095" : "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"c096" : "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"c097" : "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"c098" : "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"c099" : "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"c09a" : "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"c09b" : "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"c09c" : "TLS_RSA_WITH_AES_128_CCM",
"c09d" : "TLS_RSA_WITH_AES_256_CCM",
"c09e" : "TLS_DHE_RSA_WITH_AES_128_CCM",
"c09f" : "TLS_DHE_RSA_WITH_AES_256_CCM",
"c0a0" : "TLS_RSA_WITH_AES_128_CCM_8",
"c0a1" : "TLS_RSA_WITH_AES_256_CCM_8",
"c0a2" : "TLS_DHE_RSA_WITH_AES_128_CCM_8",
"c0a3" : "TLS_DHE_RSA_WITH_AES_256_CCM_8",
"c0a4" : "TLS_PSK_WITH_AES_128_CCM",
"c0a5" : "TLS_PSK_WITH_AES_256_CCM",
"c0a6" : "TLS_DHE_PSK_WITH_AES_128_CCM",
"c0a7" : "TLS_DHE_PSK_WITH_AES_256_CCM",
"c0a8" : "TLS_PSK_WITH_AES_128_CCM_8",
"c0a9" : "TLS_PSK_WITH_AES_256_CCM_8",
"c0aa" : "TLS_PSK_DHE_WITH_AES_128_CCM_8",
"c0ab" : "TLS_PSK_DHE_WITH_AES_256_CCM_8",
"c0ac" : "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
"c0ad" : "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
"c0ae" : "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
"c0af" : "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
"c0b0" : "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
"c0b1" : "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
"c0b2" : "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
"c0b3" : "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
"c0b4" : "TLS_SHA256_SHA256",
"c0b5" : "TLS_SHA384_SHA384",
"c100" : "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
"c101" : "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
"c102" : "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
"c103" : "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
"c104" : "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
"c105" : "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
"c106" : "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
"cca8" : "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
"cca9" : "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
"ccaa" : "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
"ccab" : "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
"ccad" : "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
"ccae" : "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
"d001" : "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
"d002" : "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
"d003" : "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
"d005" : "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
}
extensions_dict = {
"server_name": "ext_1",
"max_fragment_length" : "ext_2",
"client_certificate_url" : "ext_3",
"trusted_ca_keys" : "ext_4",
"truncated_hmac" : "ext_5",
"status_request" : "ext_6",
"user_mapping" : "ext_7",
"client_authz" : "ext_8",
"server_authz" : "ext_9",
"cert_type" : "ext_10",
"supported_groups": "ext_11",
"ec_point_formats" : "ext_12",
"srp" : "ext_13",
"signature_algorithms" : "ext_14",
"use_srtp" : "ext_15",
"heartbeat" : "ext_16",
"application_layer_protocol_negotiation" : "ext_17",
"status_request_v2" : "ext_18",
"signed_certificate_timestamp" : "ext_19",
"client_certificate_type" : "ext_20",
"server_certificate_type" : "ext_21",
"padding" : "ext_22",
"encrypt_then_mac" : "ext_23",
"extended_master_secret" : "ext_24",
"token_binding" : "ext_25",
"cached_info" : "ext_26",
"tls_lts" : "ext_27",
"compress_certificate" : "ext_28",
"record_size_limit" : "ext_29",
"pwd_protect" : "ext_30",
"pwd_clear" : "ext_31",
"password_salt" : "ext_32",
"ticket_pinning" : "ext_33",
"tls_cert_with_extern_psk" : "ext_34",
"delegated_credentials" : "ext_35",
"session_ticket": "ext_36",
"supported_ekt_ciphers" : "ext_37",
"pre_shared_key" : "ext_38",
"early_data" : "ext_39",
"supported_versions" : "ext_40",
"cookie" : "ext_41",
"psk_key_exchange_modes" : "ext_42",
"certificate_authorities" : "ext_43",
"oid_filters" : "ext_44",
"post_handshake_auth" : "ext_45",
"signature_algorithms_cert" : "ext_46",
"key_share" : "ext_47",
"transparency_info" : "ext_48",
"connection_id" : "ext_49",
"external_id_hash" : "ext_50",
"external_session_id" : "ext_51",
"renegotiation_info" : "ext_52"
}
# list that stores each tls flow as dictionary object
malicious_jsons = []
benign_jsons = []
list_of_features = ["Src_Port", "Dst_Port", "Bytes_in", "Bytes_out", "Pkts_in", "Pkts_out", "entropy", "byte_dist_std", "byte_dist_mn", "num_of_exts"]

# Creates dictionary of benign urls from magestic millions csv
for i in benign_url_file.index:
    benign_urls[str(benign_url_file["Domain"][i])] = ""

# function to get features in dictionary
def getfeatures(json_obj):
    for ext in json_obj['tls']['c_extensions']:
        if 'supported_groups' in ext:
            if ext['supported_groups'] not in supported_groups_dict:
                supported_groups_dict[ext['supported_groups']] = "sg_" + str(len(supported_groups_dict))
        if 'ec_point_formats' in ext:
            if ext['ec_point_formats'] not in ec_point_formats_dict:
                ec_point_formats_dict[ext['ec_point_formats']] = "ec_pts_" + str(len(ec_point_formats_dict))
            break

# Function that unpads and decodes server name
def unpad_decode(hex):
    server_name_hex = hex
    server_name = bytes.fromhex(server_name_hex[10:]).decode("ascii").split('.')
    server_name = server_name[len(server_name)-2] + "." + server_name[len(server_name)-1]
    return server_name

# Function that returns binary vector of supported groups
def getSGandECPointsVector(list):
    supported_groups_vector = []
    ec_points_vector = []
    for ext in list:
        if 'supported_groups' in ext:
            for i in range(len(supported_groups_dict)):
                supported_groups_vector.append(0)
            for key, value in supported_groups_dict.items():
                count=0
                if key == ext['supported_groups']:
                    supported_groups_vector[count]=1
                count+=1
        if 'ec_point_formats' in ext:
            for i in range(len(ec_point_formats_dict)):
                ec_points_vector.append(0)
            for key, value in ec_point_formats_dict.items():
                count=0
                if key == ext['ec_point_formats']:
                    ec_points_vector[count]=1
                count+=1
    return([supported_groups_vector, ec_points_vector])

# Function that returns binary vector of cipher suites
def getCipherVector(list):
    cipher_suite_vector = []
    for i in range(len(cipher_suites_dict)):
        cipher_suite_vector.append(0)
    for key, value in cipher_suites_dict.items():
        count=0
        for cs in list:
            if key == cs:
                cipher_suite_vector[count]=1
            count+=1
    return(cipher_suite_vector)

def getExtensionsVector(list):
    extensions_vector = []
    num_of_extensions = 0
    for i in range(len(extensions_dict)):
        extensions_vector.append(0)
    for key, value in extensions_dict.items():
        count=0
        for ext in list:
            if key in ext:
                num_of_extensions += 1
                extensions_vector[count]=1
            count+=1
    return([num_of_extensions, extensions_vector])

#creates json object from only reduced set of items
def cleanJson(mal_or_ben, json_obj):
    #obtaining all binary vectors from dictionary

    cleaned_list = [json_obj['sp'], json_obj['dp'], json_obj['bytes_in'], json_obj['bytes_out'], json_obj['num_pkts_in'], json_obj['num_pkts_out'], json_obj['entropy'], json_obj['byte_dist_std'], json_obj['byte_dist_mean']]
    cs_binary_vector = getCipherVector(json_obj['tls']['cs'])
    sg_binary_vector, ec_binary_vector = getSGandECPointsVector(json_obj['tls']['c_extensions'])
    num_of_extensions, ext_binary_vector = getExtensionsVector(json_obj['tls']['c_extensions'])

    #Adding features to list of features to be sent to CSV
    cleaned_list.append(num_of_extensions)
    cleaned_list.extend(cs_binary_vector)
    cleaned_list.extend(ext_binary_vector)
    cleaned_list.extend(sg_binary_vector)
    cleaned_list.extend(ec_binary_vector)

    return(cleaned_list)

# function to get rid of benign packets
def serverCheck(json_obj):
    count = 0
    try:
        server_name = ""
        for ext in json_obj['tls']['c_extensions']:
            if 'server_name' in ext:
                server_name = unpad_decode(ext['server_name'])
        if len(malicious_jsons) > 0 and json_obj['da'] == malicious_jsons[len(malicious_jsons) - 1]['da']:
            malicious_jsons.append(json_obj)
            getfeatures(json_obj)
        else:
            for name, value in benign_urls.items():
                count+=1
                if name == server_name:
                    break
                if name != server_name and count == 1000002:
                    malicious_jsons.append(json_obj)
                    getfeatures(json_obj)
    except:
        malicious_jsons.append(json_obj)
        getfeatures(json_obj)

# Function that filters out benign or malicious jsons that do not have mandatory features
def filterFiles(mal_or_ben, path_name, directory):
    for entry in directory:
        file = path_name + entry
        count=0
        with open(file, 'r') as joy_json_output:
            try:
                joy_tls_flows = joy_json_output.readlines()
                for tls_json in joy_tls_flows:
                    if count <= 300:
                        count+=1
                        tls_dict = json.loads(tls_json)
                        pkt = tls_dict['tls']
                        if 's_cert' in pkt and 'cs' in pkt and len(pkt['cs']) > 0 and len(tls_dict['packets']) >= 3 \
                        and len(pkt['srlt']) >= 3 and 'c_extensions' in pkt and len(pkt['c_extensions']) > 0 \
                        and tls_dict['sp'] and tls_dict['dp'] and tls_dict['entropy'] and tls_dict['byte_dist_std'] \
                        and tls_dict['byte_dist_mean'] and tls_dict['bytes_in'] and tls_dict['bytes_out'] \
                        and tls_dict['num_pkts_in'] and tls_dict['num_pkts_out']:
                            temp=0
                            for ext in pkt['c_extensions']:
                                if temp == 2:
                                    break
                                if 'supported_groups' in ext:
                                    temp+=1
                                if 'ec_point_formats' in ext:
                                    temp+=1
                            if temp==2:
                                if (mal_or_ben == "ben"):
                                    getfeatures(tls_dict)
                                    benign_jsons.append(tls_dict)
                                elif(mal_or_ben == "mal"):
                                    serverCheck(tls_dict)
                    else:
                        break
            finally:
                joy_json_output.close()

#function to get metadata of features (cs_bv -> ext_bv -> sg_bv -> ec_bv)
def finalizeListOfFeatures():
    for key, value in cipher_suites_dict.items():
        list_of_features.append(key)
    for key, value in extensions_dict.items():
        list_of_features.append(value)
    for key, value in supported_groups_dict.items():
        list_of_features.append(value)
    for key, value in ec_point_formats_dict.items():
        list_of_features.append(value)
    list_of_features.append("isMalware")

# Function to add extracted features to csv
def featuresToCSV(mal_or_ben, json_obj):
    file_name = ""
    if mal_or_ben == "ben":
        file_name = "benign_flows.csv"
    elif mal_or_ben == "mal":
        file_name = "malicious_flows.csv"

    with open(file_name, 'w', newline='') as cleaned_flows_list:
        try:
            writer = csv.writer(cleaned_flows_list)
            writer.writerow(list_of_features)
            if mal_or_ben == "ben":
                for obj in benign_jsons:
                    feature_list = cleanJson(mal_or_ben, obj)
                    feature_list.append(0)
                    writer.writerow(feature_list)
            elif mal_or_ben == "mal":
                for obj in malicious_jsons:
                    feature_list = cleanJson(mal_or_ben, obj)
                    feature_list.append(1)
                    writer.writerow(feature_list)
        finally:
            cleaned_flows_list.close()

#Calling functions to begin the cleaning and feature extraction process
filterFiles("ben", benign_path, benign_files_directory)
filterFiles("mal", malicious_path, malicious_files_directory)

print("Malicious Flows: ", len(malicious_jsons), " Benign Flows: ", len(benign_jsons))

#Calling functions to write tls flows to csv files
finalizeListOfFeatures()
featuresToCSV("ben", benign_jsons)
featuresToCSV("mal", malicious_jsons)

