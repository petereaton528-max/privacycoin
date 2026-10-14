/* Narrow Windows TLS adapter using existing OpenSSL APIs. No coin cryptography.
 * Implements only the two fixed operations used by the Onion transport.
 * Private output is exclusive; caller supplies verified owner-only NTFS parents.
 */
#include <stdio.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static FILE *exclusive(const wchar_t *path) {
    int fd=_wopen(path,_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY,_S_IREAD|_S_IWRITE);
    if(fd<0)return NULL;
    FILE *f=_wfdopen(fd,L"wb");
    if(!f){_close(fd);_wunlink(path);}
    return f;
}
static int extension(X509 *cert,int nid,const char *value) {
    X509_EXTENSION *ext=X509V3_EXT_conf_nid(NULL,NULL,nid,(char *)value);
    if(!ext)return 0;
    int ok=X509_add_ext(cert,ext,-1);X509_EXTENSION_free(ext);return ok;
}
static int generate(const wchar_t *key_path,const wchar_t *cert_path) {
    int ok=0,key_created=0,cert_created=0;FILE *key_file=NULL,*cert_file=NULL;
    EVP_PKEY_CTX *ctx=NULL;EVP_PKEY *key=NULL;X509 *cert=NULL;
    BIGNUM *bn=NULL;ASN1_INTEGER *serial=NULL;unsigned char random[16];
    if(wcscmp(key_path,cert_path)==0)goto cleanup;
    ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    if(!ctx || EVP_PKEY_keygen_init(ctx)<=0 || EVP_PKEY_keygen(ctx,&key)<=0)goto cleanup;
    cert=X509_new();if(!cert || !X509_set_version(cert,2))goto cleanup;
    if(RAND_bytes(random,sizeof(random))!=1)goto cleanup;
    random[0]&=0x7f;random[15]|=1;
    bn=BN_bin2bn(random,sizeof(random),NULL);if(!bn)goto cleanup;
    serial=BN_to_ASN1_INTEGER(bn,NULL);
    if(!serial || !X509_set_serialNumber(cert,serial) || !X509_set_pubkey(cert,key))goto cleanup;
    if(!X509_gmtime_adj(X509_getm_notBefore(cert),0) || !X509_gmtime_adj(X509_getm_notAfter(cert),365L*86400L))goto cleanup;
    X509_NAME *name=X509_get_subject_name(cert);
    if(!name || !X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"pc-consensus-onion",-1,-1,0) || !X509_set_issuer_name(cert,name))goto cleanup;
    if(!extension(cert,NID_basic_constraints,"critical,CA:FALSE") || !extension(cert,NID_key_usage,"critical,digitalSignature") || !extension(cert,NID_ext_key_usage,"serverAuth,clientAuth"))goto cleanup;
    if(X509_sign(cert,key,NULL)<=0)goto cleanup;
    key_file=exclusive(key_path);if(!key_file)goto cleanup;key_created=1;
    if(!PEM_write_PrivateKey(key_file,key,NULL,NULL,0,NULL,NULL) || fflush(key_file) || _commit(_fileno(key_file)))goto cleanup;
    if(fclose(key_file)){key_file=NULL;goto cleanup;}key_file=NULL;
    cert_file=exclusive(cert_path);if(!cert_file)goto cleanup;cert_created=1;
    if(!PEM_write_X509(cert_file,cert) || fflush(cert_file) || _commit(_fileno(cert_file)))goto cleanup;
    if(fclose(cert_file)){cert_file=NULL;goto cleanup;}cert_file=NULL;
    ok=1;
cleanup:
    if(key_file)fclose(key_file);
    if(cert_file)fclose(cert_file);
    if(!ok){if(cert_created)_wunlink(cert_path);if(key_created)_wunlink(key_path);}
    ASN1_INTEGER_free(serial);BN_free(bn);X509_free(cert);EVP_PKEY_free(key);EVP_PKEY_CTX_free(ctx);
    return ok?0:1;
}
static int dates(void) {
    unsigned char raw[16385];size_t n=fread(raw,1,sizeof(raw),stdin);
    if(!n || n>=sizeof(raw) || ferror(stdin))return 1;
    BIO *input=BIO_new_mem_buf(raw,(int)n),*output=NULL;X509 *cert=NULL;int ok=0;
    if(!input)goto cleanup;
    cert=PEM_read_bio_X509(input,NULL,NULL,NULL);if(!cert)goto cleanup;
    output=BIO_new_fp(stdout,BIO_NOCLOSE);if(!output)goto cleanup;
    if(BIO_puts(output,"notBefore=")<=0 || !ASN1_TIME_print(output,X509_get0_notBefore(cert)) || BIO_puts(output,"\nnotAfter=")<=0 || !ASN1_TIME_print(output,X509_get0_notAfter(cert)) || BIO_puts(output,"\n")<=0 || BIO_flush(output)<=0)goto cleanup;
    ok=1;
cleanup:
    BIO_free(output);X509_free(cert);BIO_free(input);return ok?0:1;
}
int wmain(int argc,wchar_t **argv) {
    if(argc==5 && !wcscmp(argv[1],L"x509") && !wcscmp(argv[2],L"-noout") && !wcscmp(argv[3],L"-startdate") && !wcscmp(argv[4],L"-enddate"))return dates();
    if(argc==14 && !wcscmp(argv[1],L"req") && !wcscmp(argv[2],L"-x509") && !wcscmp(argv[3],L"-newkey") && !wcscmp(argv[4],L"ed25519") && !wcscmp(argv[5],L"-nodes") && !wcscmp(argv[6],L"-keyout") && !wcscmp(argv[8],L"-out") && !wcscmp(argv[10],L"-days") && !wcscmp(argv[11],L"365") && !wcscmp(argv[12],L"-subj") && !wcscmp(argv[13],L"/CN=pc-consensus-onion"))return generate(argv[7],argv[9]);
    fputs("TLS_TOOL_FIXED_OPERATION_REQUIRED\n",stderr);return 2;
}
