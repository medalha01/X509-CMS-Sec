#ifndef E2EED740_BB73_4E5B_8AEF_DA39A6F50E32
#define E2EED740_BB73_4E5B_8AEF_DA39A6F50E32

#include <stdint.h>
#include <stdio.h>
#include <iostream>

#include <openssl/pem.h>

#include <openssl/evp.h>

#include <openssl/bio.h>

#include <openssl/cms.h>

#include <openssl/safestack.h>

#include <openssl/err.h>

#include <vector>

#include <openssl/x509.h>

#include <inttypes.h>

#include <string.h>

#include <string>

#include <time.h>

#define NULL nullptr
// Definindo a estrutura de um ByteArray
typedef struct ByteArray
{
    // Um ponteiro para um array de bytes (dados binários/uint8/unsigned char)
    unsigned char *data{nullptr};
    // Tamanho (comprimento) do array de bytes
    size_t len{0};

    // Sobrecarga do operador de igualdade para comparar dois objetos ByteArray
    bool operator==(const ByteArray &other)
    {
        // Compara os tamanhos (len) e o conteúdo dos arrays de bytes (data)
        return len == other.len &&
               (memcmp(data, other.data, len) == 0);
    }

    // Destrutor da estrutura
    ~ByteArray()
    {
        // Verifica se o ponteiro "data" não é nulo antes de liberar a memória
        if (data != nullptr)
            delete[] data;
    }
} ByteArray;

typedef struct CrlUpdateInfo
{

    char *lastUpdate;
    char *nextUpdate;
    bool isExpired;
    bool errorStatus;

} CrlUpdateInfo;

// Código depreciado
struct VerificationResponse
{
    char *verificationType;
    char *validChain;
    char *signature;
    char *result;
    int code;
};
//
// Estrutura de Resposta de uma verificação, contendo o booleano da resposta e a mensagem de erro
struct Response
{
    bool isValid;
    char *response;
};

// Definindo uma estrutura de dados chamada "ChainByteArrays"
struct ChainByteArrays
{
    // Ponteiros para objetos do tipo "ByteArray" que representam diferentes certificados
    ByteArray *endCertificate = nullptr;          // Certificado final
    ByteArray *intermediaryCertificate = nullptr; // Certificado intermediário
    ByteArray *rootCertificate = nullptr;         // Certificado raiz
};

// Definindo uma estrutura de dados chamada "Links"
struct Links
{
    // Um ponteiro para um array de ponteiros para strings (URLs)
    char **links;

    // Um inteiro que representa o tamanho do conjunto de URLs
    int size;
};

// Definindo uma estrutura de dados chamada "CertificateInformation"
struct CertificateInformation
{
    // Ponteiros para strings que representam informações de um certificado
    char *issuerCN;                // Nome Comum (Common Name) do emissor
    char *subjectCN;               // Nome Comum (Common Name) do titular
    char *subjectCountry;          // País do titular
    char *subjectOrganization;     // Organização do titular
    char *subjectOrganizationUnit; // Unidade de Organização do titular
    char *serialNumber;            // Número de série do certificado
    char *lastcrlDateInformation;  // Data da última atualização da Lista de Certificados Revogados (CRL)
    char *nextcrlDateInformation;  // Data da próxima atualização da CRL
    char *validFrom;               // Data de início de validade do certificado
    char *validTo;                 // Data de término de validade do certificado
    char *revoked;                 // Indica se o certificado foi revogado
    bool expired;                  // Indica se o certificado está expirado
    bool signatureIsValid;         // Indica se a assinatura do certificado é válida
};

extern "C"
{

    // Função para liberar a memória associada a uma estrutura CMS_ContentInfo
    void freeCMSSignature(CMS_ContentInfo *signature)
    {
        CMS_ContentInfo_free(signature);
    }

    // Função para liberar a memória associada a um certificado X.509
    void freeX509Certificate(X509 *certificate)
    {
        X509_free(certificate);
    }

    // Função para inicializar a biblioteca OpenSSL para criptografia
    void startOpenSSL()
    {
        OPENSSL_init_crypto(0, NULL);
    }

    // Código depreciado
    //  Decodifica certificado X509 codificad    o em PEM ou DER
    X509_CRL *pem2crl(ByteArray *pem)
    {
        X509_CRL *crl = nullptr;
        BIO *crlbio = nullptr, *outbio = nullptr;

        /* ---------------------------------------------------------- *
         * These function calls initialize openssl for correct work.  *
         * ---------------------------------------------------------- */
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();

        crlbio = BIO_new_mem_buf(pem->data, pem->len);
        if (!crlbio)
        {
            fprintf(stderr, "Failed to create memory buffer BIO\n");
            return nullptr;
        }
        outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!outbio)
        {
            BIO_free(crlbio);
            fprintf(stderr, "Failed to create stdout BIO\n");
            return nullptr;
        }

        /* Load the crl from file (PEM) */
        crl = PEM_read_bio_X509_CRL(crlbio, nullptr, 0, NULL);
        if (!crl)
        {
            BIO_free(outbio);
            BIO_free(crlbio);
            fprintf(stderr, "Failed to read X509_CRL from PEM data\n");
            return nullptr;
        }

        if (crlbio)
            BIO_free(crlbio);
        if (outbio)
            BIO_free(outbio);

        return crl;
    }

    X509 *pem2x509(ByteArray *pem)
    {
        X509 *cert = nullptr;
        BIO *certbio = nullptr;
        BIO *outbio = nullptr;

        /* ---------------------------------------------------------- *
         * These function calls initialize openssl for correct work.  *
         * ---------------------------------------------------------- */
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Create the Input/Output BIO's */
        certbio = BIO_new_mem_buf(pem->data, pem->len);
        if (!certbio)
        {

            return nullptr;
        }
        outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

        if (!outbio)
        {
            BIO_free(certbio);
            return nullptr;
        }

        /* Load the certificate from file (PEM) */
        cert = PEM_read_bio_X509(certbio, nullptr, 0, NULL);
        if (!cert)
        {
            BIO_free(certbio);
            BIO_free(outbio);
            return nullptr;
        }

        /* ---------------------------------------------------------- *
         * These function calls remove flagged errors and free memory *
         * ---------------------------------------------------------- */

        BIO_free(certbio);
        BIO_free(outbio);

        return cert;
    }

    X509 *decode_x509(ByteArray *bytes)
    {
        X509 *px509{
            nullptr};

        const unsigned char *buf = reinterpret_cast<
            const unsigned char *>(bytes->data);
        std::string s(reinterpret_cast<char const *>(bytes->data));

        if (s.find("-----BEGIN CERTIFICATE-----") != std::string::npos)
            px509 = pem2x509(bytes);
        else
            px509 = d2i_X509(nullptr, &buf, bytes->len);

        return px509;
    }

    // Decodifica crl codificada em PEM ou DER
    X509_CRL *decode_crl(ByteArray *bytes)
    {
        X509_CRL *pcrl{
            nullptr};

        const unsigned char *buf = reinterpret_cast<
            const unsigned char *>(bytes->data);
        std::string s(reinterpret_cast<char const *>(bytes->data));

        if (s.find("-----BEGIN X509 CRL-----") != std::string::npos)
            pcrl = pem2crl(bytes);
        else
            pcrl = d2i_X509_CRL(nullptr, &buf, bytes->len);

        return pcrl;
    }
    // Fim do código depreciado;

    /**
     * A função decodifica uma assinatura CMS apartir de um array de bytes usando funções da biblioteca OpenSSL.
     *
     * @param signature Um ponteiro para um objeto ByteArray que contém os dados da assinatura a ser decodificada.
     *
     * @return Um ponteiro para uma estrutura CMS_ContentInfo, que representa a assinatura CMS decodificada.
     */
    CMS_ContentInfo *decodeSignature(ByteArray *signature)
    {
        CMS_ContentInfo *decodedCMSSignature = nullptr;
        BIO *signatureMemoryBuffer = nullptr;

        // Inicializa OpenSSL com algoritmos, cifras e digesters
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();

        // Cria um BIO de buffer de memória para armazenar os dados da assinatura
        signatureMemoryBuffer = BIO_new_mem_buf(signature->data, signature->len);
        if (signatureMemoryBuffer == nullptr)
        {
            fprintf(stderr, "Erro ao criar o BIO de buffer de memória\n");
            return nullptr;
        }

        // Decodifica a assinatura usando a função d2i_CMS_bio
        decodedCMSSignature = d2i_CMS_bio(signatureMemoryBuffer, nullptr);
        if (decodedCMSSignature == nullptr)
        {
            fprintf(stderr, "Erro ao decodificar a assinatura CMS\n");
            BIO_free(signatureMemoryBuffer);
            return nullptr;
        }

        // Libera o BIO de buffer de memória
        BIO_free(signatureMemoryBuffer);

        return decodedCMSSignature;
    }

    /**
     * Esta função decodifica um certificado X.509 no formato PEM ou DER.
     *
     * @param x509Certificate Um ponteiro para um objeto ByteArray que contém os dados do certificado X.509 a ser decodificado.
     *
     * @return Um ponteiro para uma estrutura X509, que representa um certificado X.509.
     */
    X509 *decodeCertificate(ByteArray *x509Certificate)
    {
        // Inicializa OpenSSL com algoritmos, cifras e digesters
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();

        X509 *certificate = nullptr;

        // Verifica se o objeto ByteArray é válido e contém dados
        if (x509Certificate == nullptr || x509Certificate->data == nullptr || x509Certificate->len <= 0)
        {
            return nullptr;
        }

        // Cria um BIO de buffer de memória com os dados do certificado
        BIO *bio = BIO_new_mem_buf(x509Certificate->data, x509Certificate->len);

        if (bio != nullptr)
        {
            // Tenta decodificar o certificado no formato PEM
            if (PEM_read_bio_X509(bio, &certificate, nullptr, nullptr) == nullptr)
            {
                // Se falhar como PEM, tenta decodificar no formato DER
                BIO_reset(bio);
                if (d2i_X509_bio(bio, &certificate) == nullptr)
                {
                    // Falha na decodificação como DER também
                    return nullptr;
                }
            }

            // Libera o BIO
            BIO_free(bio);
        }

        return certificate;
    }

    /**
     * Esta função decodifica uma entrada de bytes de CRL X509, que pode estar no formato PEM ou DER, e
     * retorna a CRL X509 decodificada.
     *
     * @param bytesFromCrl Um ponteiro para um objeto ByteArray que contém os bytes da CRL X509 a ser
     * decodificada.
     *
     * @return Um ponteiro para uma estrutura X509_CRL, que representa uma Lista de Revogação de Certificados X.509 (CRL) decodificada.
     */
    X509_CRL *decodeCRLs(ByteArray *bytesFromCrl)
    {
        // Verifica se o objeto ByteArray de entrada é válido e contém dados válidos
        if (bytesFromCrl == nullptr || bytesFromCrl->data == nullptr || bytesFromCrl->len <= 0)
        {
            return nullptr;
        }

        X509_CRL *decodedCrl = nullptr; // Inicializa o ponteiro de CRL como nulo

        const unsigned char *data = bytesFromCrl->data;

        // Valida a entrada e cria um BIO de buffer de memória
        BIO *bio = BIO_new_mem_buf(data, bytesFromCrl->len);

        // Verifica se o BIO foi criado com sucesso
        if (bio == nullptr)
        {
            return nullptr;
        }

        // Tenta decodificar como DER (formato binário)
        d2i_X509_CRL_bio(bio, &decodedCrl);

        // Se a decodificação como DER falhar, tenta o formato PEM (formato base64)
        if (decodedCrl == nullptr)
        {
            BIO_reset(bio);
            PEM_read_bio_X509_CRL(bio, &decodedCrl, NULL, NULL);
        }

        BIO_free(bio); // Libera o BIO

        return decodedCrl; // Retorna a CRL decodificada (pode ser nullptr se a decodificação falhar)
    }

    /**
     * Esta função adiciona um certificado de signatário a uma assinatura CMS.
     *
     * @param signature Um array de bytes representando a assinatura CMS à qual o certificado do signatário
     * precisa ser adicionado.
     * @param signerCertificate Um array de bytes contendo a representação binária do certificado X.509 do signatário.
     *
     * @return Um ponteiro CMS_ContentInfo, que representa a assinatura com o certificado do signatário adicionado a ela.
     */
    CMS_ContentInfo *addCertificateToSignature(ByteArray *signature, ByteArray *signerCertificate)
    {
        // Decodifica o certificado do signatário
        X509 *signerX509Certificate = decodeCertificate(signerCertificate);
        if (!signerX509Certificate)
        {
            fprintf(stderr, "Erro ao decodificar o certificado X509\n");
            return nullptr;
        }

        // Decodifica a assinatura
        CMS_ContentInfo *decodedSignature = decodeSignature(signature);
        if (!decodedSignature)
        {
            fprintf(stderr, "Erro ao decodificar a assinatura CMS\n");
            freeX509Certificate(signerX509Certificate);
            return nullptr;
        }

        // Adiciona o certificado do signatário à assinatura
        if (!CMS_add1_cert(decodedSignature, signerX509Certificate))
        {
            fprintf(stderr, "Erro ao adicionar o certificado à assinatura\n");
            freeX509Certificate(signerX509Certificate);
            CMS_ContentInfo_free(decodedSignature);
            return nullptr;
        }

        // Libera o certificado do signatário, uma vez que foi adicionado à assinatura
        freeX509Certificate(signerX509Certificate);
        return decodedSignature;
    }

    /**
     * Esta função adiciona uma cadeia de certificados a uma pilha de certificados intermediários (STACK_OF(X509)).
     *
     * @param certificateChain Um array de ponteiros ByteArray que contém os certificados a serem adicionados.
     * @param chainSize O tamanho da cadeia de certificados.
     * @param intermediaryCertsStack Uma pilha de certificados intermediários (STACK_OF(X509)) à qual os certificados serão adicionados.
     *
     * @return Retorna true se a adição dos certificados à pilha for bem-sucedida, ou false em caso de erro.
     */
    bool addCertificatesToStack(ByteArray **certificateChain, size_t chainSize, STACK_OF(X509) * intermediaryCertsStack)
    {
        X509 *stackCert = nullptr;
        for (size_t k = 0; k < chainSize; k++)
        {
            // Verifica se o certificado na cadeia é válido
            if (certificateChain[k] == nullptr || certificateChain[k]->data == nullptr || certificateChain[k]->len <= 0)
            {
                continue; // Ignora certificado inválido
            }

            // Decodifica o certificado da cadeia
            stackCert = decodeCertificate(certificateChain[k]);
            if (!stackCert)
            {
                return false; // Retorna false em caso de erro na decodificação
            }

            // Adiciona o certificado à pilha de certificados intermediários
            sk_X509_push(intermediaryCertsStack, stackCert);
        }
        return true; // Retorna true se todos os certificados foram adicionados com sucesso
    }

    /**
     * Esta função adiciona uma lista de revogação de certificados (CRL) a um armazenamento de certificados X.509.
     *
     * @param crlList Um array de ponteiros ByteArray que contém as CRLs a serem adicionadas.
     * @param crlSize O tamanho da lista de CRLs.
     * @param store Um armazenamento de certificados X.509 ao qual as CRLs serão adicionadas.
     */
    void addCrlsToStore(ByteArray **crlList, size_t crlSize, X509_STORE *store)
    {
        X509_CRL *crl = nullptr;

        // Itera sobre a lista de CRLs
        for (size_t i = 0; i < crlSize; i++)
        {
            ByteArray *crlBytes = crlList[i];
            if (crlBytes == nullptr)
            {
                continue; // Ignora se a CRL for inválida
            }

            // Decodifica a CRL a partir dos bytes
            crl = decodeCRLs(crlBytes);
            if (crl == nullptr)
            {
                X509_STORE_free(store);
                return; // Retorna se a decodificação da CRL falhar
            }

            // Adiciona a CRL ao armazenamento de certificados
            if (X509_STORE_add_crl(store, crl) != 1)
            {
                // Se a adição da CRL ao armazenamento falhar, registra um erro e libera a CRL
                X509_STORE_free(store);
                X509_CRL_free(crl);
                return;
            }
        }
    }

    /**
     * Esta função adiciona uma cadeia de certificados a um armazenamento de certificados X.509.
     *
     * @param chain Um array de ponteiros ByteArray que contém os certificados a serem adicionados.
     * @param chainSize O tamanho da cadeia de certificados.
     * @param store Um armazenamento de certificados X.509 ao qual os certificados serão adicionados.
     */
    void addChainToStore(ByteArray **chain, size_t chainSize, X509_STORE *store)
    {
        // Itera sobre a cadeia de certificados
        for (unsigned int i = 0; i < chainSize; i++)
        {
            ByteArray *certificateBytes = chain[i];
            X509 *decodedCertificate = decodeCertificate(certificateBytes);

            // Verifica se a decodificação do certificado foi bem-sucedida
            if (!decodedCertificate)
            {
                X509_STORE_free(store);
                return; // Retorna em caso de falha na decodificação
            }

            // Adiciona o certificado ao armazenamento
            if (X509_STORE_add_cert(store, decodedCertificate) != 1)
            {
                X509_free(decodedCertificate); // Libera o certificado
                X509_STORE_free(store);
                return; // Retorna em caso de falha na adição do certificado
            }

            X509_free(decodedCertificate); // Libera o certificado após a adição bem-sucedida
        }
    }

    /**
     * Esta função verifica uma assinatura CMS usando uma cadeia de certificados e um buffer de mensagem.
     *
     * @param bytesFromData Um array de bytes contendo os dados a serem verificados.
     * @param signature Um array de bytes contendo a assinatura a ser verificada.
     * @param certificate Um array de bytes contendo o certificado usado para assinar os dados.
     * @param certificateChain Um array de ponteiros para ByteArrays representando a cadeia de certificados. O
     * tamanho do array é dado por chainSize.
     * @param chainSize O tamanho da cadeia de certificados, que é o número de certificados na cadeia.
     *
     * @return um objeto de resposta, que contém um valor booleano indicando se a assinatura é válida
     * ou não, e uma string de mensagem fornecendo informações adicionais sobre o resultado da verificação.
     */
    Response verifyCmsSignature(
        ByteArray *bytesFromData,
        ByteArray *signature,
        ByteArray *certificate,
        ByteArray **certificateChain,
        size_t chainSize)
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Cria um novo objeto X509_STORE
        X509_STORE *rootStore = X509_STORE_new();

        if (rootStore == nullptr)
        {
            return {
                false,
                "Falha ao criar objeto X509_STORE"};
        }

        // Adiciona a cadeia de certificados ao armazenamento
        addChainToStore(certificateChain, chainSize, rootStore);
        if (!rootStore)
        {
            X509_STORE_free(rootStore);
            return {
                false,
                "Falha ao adicionar cadeia de certificados ao X509_STORE"};
        }

        // Adiciona o certificado à assinatura
        CMS_ContentInfo *decodedSignature = addCertificateToSignature(signature, certificate);

        if (decodedSignature == nullptr)
        {
            X509_STORE_free(rootStore);
            return {
                false,
                "Falha ao adicionar certificado à assinatura"};
        }

        // Cria um novo objeto BIO para o buffer de mensagem
        BIO *messageBuffer = BIO_new_mem_buf(bytesFromData->data, bytesFromData->len);

        if (messageBuffer == nullptr)
        {
            CMS_ContentInfo_free(decodedSignature);
            X509_STORE_free(rootStore);
            return {
                false,
                "Falha ao criar objeto BIO"};
        }

        // Verifica a assinatura
        int verificationResult = CMS_verify(
            decodedSignature,
            nullptr,
            rootStore,
            messageBuffer,
            nullptr,
            CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY);

        // Libera recursos
        CMS_ContentInfo_free(decodedSignature);
        BIO_free(messageBuffer);
        X509_STORE_free(rootStore);

        // Verifica o resultado da verificação
        if (verificationResult == 1)
        {
            return {
                true,
                "Assinatura válida"};
        }
        else if (verificationResult == 0)
        {
            return {
                false,
                "Assinatura inválida"};
        }
        else
        {
            return {
                false,
                "Falha na verificação da assinatura"};
        }
    }

    /**
     * A função "getNIDInformation" recupera uma informação específica de uma estrutura X509_NAME
     * usando um NID (Name Identifier) fornecido.
     *
     * @param name Um ponteiro para uma estrutura X509_NAME, que representa o nome de uma entidade em um
     * certificado X.509.
     * @param nid O parâmetro "nid" representa o "Name Identifier" (Identificador de Nome) e é um valor inteiro
     * que representa o atributo ou campo específico na estrutura X509_NAME de onde deseja-se recuperar
     * a informação. Cada atributo na estrutura X509_NAME possui um valor NID único.
     *
     * @return um ponteiro para um array de caracteres (string) contendo a informação associada ao
     * NID (Identificador de Nome) especificado na estrutura X509_NAME fornecida.
     */
    char *getNIDInformation(X509_NAME *name, int nid)
    {
        int index = X509_NAME_get_index_by_NID(name, nid, -1);

        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
        ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
        auto *string = (char *)ASN1_STRING_get0_data(asn1);
        return string;
    }

    /**
     * A função isCertificateRevoked verifica se um certificado de destino foi revogado, verificando-o
     * em relação a uma lista de Listas de Revogação de Certificados (CRLs) usando o certificado do emissor.
     *
     * @param targetCertificate Um ponteiro para o certificado X509 que precisa ser verificado quanto à
     * revogação.
     * @param crls Um array de ponteiros para objetos ByteArray, que representam as Listas de Revogação de Certificados (CRLs)
     * no formato binário.
     * @param crlSize O parâmetro crlSize representa o número de Listas de Revogação de Certificados (CRLs)
     * no array crls.
     * @param issuerCertificate O parâmetro issuerCertificate é um ponteiro para uma estrutura X509
     * que representa o certificado do emissor do certificado de destino.
     *
     * @return um valor booleano. Retorna true se o certificado de destino foi revogado e false caso contrário.
     */
    bool isCertificateRevoked(X509 *targetCertificate, ByteArray **crls, size_t crlSize, X509 *issuerCertificate)
    {
        STACK_OF(X509_CRL) * crlStack;
        crlStack = sk_X509_CRL_new_null();

        // Itera sobre as Listas de Revogação de Certificados (CRLs)
        for (int i = 0; i < crlSize; i++)
        {
            X509_CRL *decodedCrl = decodeCRLs(crls[i]);
            if (decodedCrl)
            {
                sk_X509_CRL_push(crlStack, decodedCrl);
            }
        }

        EVP_PKEY *issuerKey = X509_get_pubkey(issuerCertificate);
        ASN1_INTEGER *serial = X509_get_serialNumber(targetCertificate);

        // Itera sobre as CRLs na pilha
        for (int i = 0; i < sk_X509_CRL_num(crlStack); i++)
        {
            X509_CRL *crlFile = sk_X509_CRL_value(crlStack, i);
            if (crlFile)
            {
                int revocationCheck = X509_CRL_verify(crlFile, issuerKey);

                // Verifica se a CRL é válida
                if (revocationCheck == 1)
                {
                    X509_REVOKED *revoked;

                    // Verifica se o certificado de destino está na lista de revogação
                    return X509_CRL_get0_by_serial(crlFile, &revoked, serial) == 1;
                }
            }
        }
        return false;
    }
    /**
     * A função isCertificateExpired verifica se o horário atual está dentro do período de validade de um
     * certificado.
     *
     * @param not_before Um ponteiro para um objeto ASN1_TIME que representa o horário de início do
     * período de validade do certificado.
     * @param not_after Um ponteiro para um objeto ASN1_TIME que representa
     * a data e hora de expiração de um certificado.
     *
     * @return um valor booleano. Retorna true se o horário atual estiver fora do período de validade do
     * certificado (ou seja, o certificado expirou ou ainda não é válido) e false caso contrário.
     */
    bool isCertificateExpired(const ASN1_TIME *not_before, const ASN1_TIME *not_after)
    {
        time_t *ptime;
        bool expiratedFlag = false;

        // Obtém o horário atual
        time_t actualtime = time(nullptr);
        ptime = &actualtime;

        // Compara o horário atual com a data de início do certificado (not_before)
        int resultNotBefore = X509_cmp_time(not_before, ptime);

        // Compara o horário atual com a data de expiração do certificado (not_after)
        int resultNotAfter = X509_cmp_time(not_after, ptime);

        // Se o resultado da comparação indicar que o certificado não é mais válido
        if (resultNotBefore > 0 || resultNotAfter < 0)
        {
            // Define a flag de expiração como true
            expiratedFlag = true;
        }

        // Retorna a flag de expiração
        return expiratedFlag;
    }

    bool isCrlExpired(const ASN1_TIME *nextUpdate)
    {
        time_t *ptime;
        bool expiratedFlag = false;

        // Obtém o horário atual
        time_t actualtime = time(nullptr);
        ptime = &actualtime;

        // Compara o horário atual com a data de expiração do certificado (not_after)
        int resultNotAfter = X509_cmp_time(nextUpdate, ptime);

        // Se o resultado da comparação indicar que o certificado não é mais válido
        if (resultNotAfter < 0)
        {
            // Define a flag de expiração como true
            expiratedFlag = true;
        }

        // Retorna a flag de expiração
        return expiratedFlag;
    }
    /**
     * Verifica se um certificado está revogado ou não com base em uma lista de CRLs.
     *
     * @param targetCertificate O certificado alvo que será verificado.
     * @param crls Um ponteiro para um array de ponteiros para ByteArray, que contém a lista de CRLs.
     * @param crlSize O tamanho da lista de CRLs.
     * @param issuerCertificate O certificado emissor usado para a verificação.
     *
     * @return Uma string indicando o status de revogação do certificado:
     *         - "Revogado" se o certificado estiver revogado.
     *         - "Não revogado" se o certificado não estiver revogado.
     */
    char *isCertificateRevokedAdapter(X509 *targetCertificate, ByteArray **crls, size_t crlSize, X509 *issuerCertificate)
    {
        if (isCertificateRevoked(targetCertificate, crls, crlSize, issuerCertificate) == true)
        {
            return "Revogado";
        }
        return "Nao revogado";
    }

    /**
     * A função asn1_timeToString converte um objeto ASN1_TIME em uma representação de string.
     *
     * @param time Um ponteiro para uma estrutura ASN1_TIME, que representa um valor de tempo no formato ASN.1.
     *
     * @return A função asn1_timeToString retorna um array de caracteres alocado dinamicamente (char*)
     * que representa o valor ASN1_TIME como uma string.
     */
    char *asn1_timeToString(const ASN1_TIME *time)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            return nullptr;
        }

        if (ASN1_TIME_print(bio, time) <= 0)
        {
            BIO_free(bio);
            return nullptr;
        }

        char *charTime = nullptr;
        long length = BIO_get_mem_data(bio, &charTime);
        char *result = new char[length + 1];
        memcpy(result, charTime, length);
        result[length] = '\0';

        BIO_free(bio);

        return result;
    }

    /**
     * A função get_serial_number recebe um certificado X509 como entrada e retorna o número de série do
     * certificado como uma string hexadecimal.
     *
     * @param certificate O parâmetro "certificate" é do tipo X509, que é uma estrutura que representa um
     * certificado X.509.
     *
     * @return uma representação hexadecimal do número de série do certificado X509 fornecido.
     */
    char *get_serial_number(X509 *certificate)
    {
        ASN1_INTEGER *serialNumber = X509_get_serialNumber(certificate);
        BIGNUM *bnSerialNumber = ASN1_INTEGER_to_BN(serialNumber, NULL);
        return BN_bn2hex(bnSerialNumber);
    }

    /**
     * A função verifica se um certificado de destino é assinado por um certificado emissor.
     *
     * @param targetCert Um array de bytes contendo o certificado de destino que precisa ser verificado se
     * foi assinado pelo certificado emissor.
     * @param issuerCert Um array de bytes contendo o certificado do emissor codificado.
     *
     * @return um valor booleano indicando se o certificado de destino é assinado pelo certificado emissor.
     */
    bool isCertSignedBy(ByteArray *targetCert, ByteArray *issuerCert)
    {
        X509 *target = decodeCertificate(targetCert);
        X509 *issuer = decodeCertificate(issuerCert);

        if (target == nullptr || issuer == nullptr)
        {
            return false;
        }

        EVP_PKEY *issuerKey = X509_get_pubkey(issuer);
        if (issuerKey == nullptr)
        {
            X509_free(target);
            X509_free(issuer);
            return false;
        }
        bool isSigned = X509_verify(target, issuerKey);

        return isSigned;
    }

    /**
     * A função verifica a assinatura de um certificado usando a chave pública do emissor.
     *
     * @param certificate O parâmetro certificate é um ponteiro para uma estrutura X509 que representa o
     * certificado que precisa ser verificado. Este certificado contém a chave pública e outras informações
     * sobre a entidade para a qual o certificado foi emitido.
     * @param issuer O parâmetro issuer é um ponteiro para uma estrutura X509 que representa o
     * certificado do emissor. Este certificado é usado para verificar a assinatura do parâmetro certificate.
     *
     * @return um valor booleano indicando se a assinatura do certificado é verificada pela chave pública do emissor.
     */
    bool verifyCertSignature(X509 *certificate, X509 *issuer)
    {

        EVP_PKEY *issuerKey = X509_get_pubkey(issuer);

        bool isSigned = X509_verify(certificate, issuerKey);

        return isSigned;
    }

    /**
     * A função getCRLFromCert obtém a Lista de Revogação de Certificados (CRL) correspondente a um certificado de destino,
     * verificando-o em relação a uma lista de CRLs usando a chave pública do emissor do certificado.
     *
     * @param crls Um array de ponteiros para objetos ByteArray, que representam as Listas de Revogação de Certificados (CRLs)
     * no formato binário.
     * @param crlSize O parâmetro crlSize representa o número de Listas de Revogação de Certificados (CRLs)
     * no array crls.
     * @param certificate Um ponteiro para o certificado X509 de destino.
     *
     * @return Um ponteiro para a CRL correspondente ao certificado de destino, ou nullptr se a CRL não for encontrada ou não for válida.
     */
    X509_CRL *getCRLFromCert(ByteArray **crls, size_t crlSize, X509 *certificate)
    {
        EVP_PKEY *issuerKey = X509_get_pubkey(certificate);
        X509_CRL *decodedCrl = nullptr;

        if (issuerKey == nullptr)
        {
            return nullptr;
        }

        for (size_t j = 0; j < crlSize - 1; j++)
        {
            decodedCrl = decodeCRLs(crls[j]);

            if (decodedCrl == nullptr)
            {
                continue;
            }

            int revocationCheck = X509_CRL_verify(decodedCrl, issuerKey);
            // checamos a revogação da CRL. Caso seja sucesso, ou seja, não revogada, a funcão retorna 1
            // e entra no if. Caso contrário, não entra.
            if (revocationCheck == 1)
            {
                return decodedCrl;
            }
            X509_CRL_free(decodedCrl);
        }

        return nullptr;
    }

    /**
     * A função getCertificateInformation recupera várias informações de um certificado fornecido,
     * como os nomes comuns do emissor e do assunto, número de série, período de validade e se o
     * certificado está expirado ou revogado.
     *
     * @param certificate Um ponteiro para um objeto ByteArray que contém os dados do certificado.
     * @param crls Um array de ponteiros para objetos ByteArray que representam as Listas de Revogação de Certificados (CRLs). Pode ser nulo
     * @param crlsSize O parâmetro crlsSize representa o tamanho do array crls, que contém
     * ponteiros para objetos ByteArray representando as Listas de Revogação de Certificados (CRLs). Pode ser nulo.
     * @param issuerCertificate Um ponteiro para um objeto ByteArray que contém o certificado do emissor.
     * Esse parâmetro pode ser nullptr se não houver certificado do emissor. Se esse parâmetro for nulo,
     * não será feita a verificação de revogação do certificado.
     *
     * @return uma estrutura do tipo CertificateInformation com todas as informações relevantes do certificado.
     */
    CertificateInformation getCertificateInformation(
        ByteArray *certificate,
        ByteArray **crls,
        size_t crlsSize,
        ByteArray *issuerCertificate)
    {
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();

        CertificateInformation certificateInformation;
        X509 *decodedCertificate = decodeCertificate(certificate);
        X509 *decodedIssuerCertificate = issuerCertificate != nullptr ? decodeCertificate(issuerCertificate) : nullptr;

        // Inicializa os campos da estrutura CertificateInformation
        X509_NAME *subjectCN = nullptr;
        X509_NAME *issuerCN = nullptr;
        ASN1_TIME *validFrom = nullptr;
        ASN1_TIME *validTo = nullptr;
        X509_CRL *decodedCRL = nullptr;
        certificateInformation.revoked = "Indeterminado";
        certificateInformation.signatureIsValid = false;
        certificateInformation.lastcrlDateInformation = "Indeterminado";
        certificateInformation.nextcrlDateInformation = "Indeterminado";
        const ASN1_TIME *lastcrlDateInformationTime = nullptr;
        const ASN1_TIME *nextcrlDateInformationTime = nullptr;

        // Verifica se há CRLs disponíveis
        if (crlsSize > 0)
        {
            decodedCRL = getCRLFromCert(crls, crlsSize, decodedCertificate);
        }

        // Verifica se o certificado de destino está revogado
        if (crls != nullptr && issuerCertificate != nullptr)
        {
            char *revokedResult = isCertificateRevokedAdapter(
                decodedCertificate, crls, crlsSize, decodedIssuerCertificate);
            certificateInformation.revoked = revokedResult;
        }

        // Verifica se a assinatura do certificado é válida
        if (decodedCertificate != nullptr && issuerCertificate != nullptr)
        {
            certificateInformation.signatureIsValid = verifyCertSignature(decodedCertificate, decodedIssuerCertificate);
        }

        if (decodedCertificate != nullptr)
        {
            subjectCN = X509_get_subject_name(decodedCertificate);
            issuerCN = X509_get_issuer_name(decodedCertificate);
            validFrom = X509_getm_notBefore(decodedCertificate);
            validTo = X509_getm_notAfter(decodedCertificate);
        }

        // Obtém o nome comum (CN) do emissor
        if (issuerCN)
        {
            certificateInformation.issuerCN = getNIDInformation(issuerCN, NID_commonName);
        }
        else
        {
            certificateInformation.issuerCN = "Não informado";
        }

        // Obtém o nome comum (CN) do assunto
        certificateInformation.subjectCN = getNIDInformation(subjectCN, NID_commonName);

        // Obtém o número de série do certificado
        certificateInformation.serialNumber = get_serial_number(decodedCertificate);

        // Obtém informações adicionais, como país, organização e unidade organizacional
        certificateInformation.subjectCountry = getNIDInformation(subjectCN, NID_countryName);
        certificateInformation.subjectOrganization = getNIDInformation(subjectCN, NID_organizationName);
        certificateInformation.subjectOrganizationUnit = getNIDInformation(subjectCN, NID_organizationalUnitName);

        // Obtém datas de início e término de validade do certificado
        certificateInformation.validFrom = asn1_timeToString(validFrom);
        certificateInformation.validTo = asn1_timeToString(validTo);

        // Verifica se o certificado está expirado
        certificateInformation.expired = isCertificateExpired(X509_get0_notBefore(decodedCertificate), X509_get0_notAfter(decodedCertificate));

        // Obtém informações de data de última e próxima atualização da CRL

        if (decodedCRL != nullptr)
        {
            lastcrlDateInformationTime = X509_CRL_get0_lastUpdate(decodedCRL);
            nextcrlDateInformationTime = X509_CRL_get0_nextUpdate(decodedCRL);

            // Verifica se as datas da CRL são válidas
            if (
                lastcrlDateInformationTime && nextcrlDateInformationTime &&
                strlen(certificateInformation.lastcrlDateInformation) >= 5 &&
                strlen(certificateInformation.nextcrlDateInformation) >= 5)
            {
                certificateInformation.lastcrlDateInformation = asn1_timeToString(lastcrlDateInformationTime);
                certificateInformation.nextcrlDateInformation = asn1_timeToString(nextcrlDateInformationTime);
            }

            // Libera a memória da CRL
            X509_CRL_free(decodedCRL);
        }

        // Libera a memória dos certificados
        freeX509Certificate(decodedIssuerCertificate);
        freeX509Certificate(decodedCertificate);

        return certificateInformation;
    }

    /**
     * A função getCAIssuer obtém a informação do emissor de certificados de autoridade (CA)
     * contida em um certificado X.509, quando disponível.
     *
     * @param certificate Um ponteiro para um objeto ByteArray que contém os dados do certificado.
     *
     * @return uma string que representa o emissor de certificados de autoridade (CA) do certificado,
     * ou nullptr se a informação não estiver disponível.
     */
    char *getCAIssuer(ByteArray *certificate)
    {
        // Decodifica o certificado X.509
        X509 *decodedCertificate = decodeCertificate(certificate);

        if (decodedCertificate == nullptr)
        {
            return "Extension not found.";
        }
        int ext_nid = OBJ_txt2nid("1.3.6.1.5.5.7.1.1");

        X509_EXTENSION *ext = X509_get_ext(decodedCertificate, X509_get_ext_by_NID(decodedCertificate, ext_nid, -1));
        if (!ext)
        {
            return "Extension not present in the certificate.";
        }

        ASN1_OCTET_STRING *asn1_str = X509_EXTENSION_get_data(ext);

        if (!asn1_str)
        {
            return "Extension data not found.";
        }
        // Convert ASN.1 octet string to a C string
        char *asn1_string(reinterpret_cast<char *>(asn1_str->data));

        return asn1_string;
    }

    /**
     * A função getCrlUpdateInfoTime recebe um array de CRLs, encontra o horário da última atualização entre eles
     * e retorna-o como uma string.
     *
     * @param crlList Um ponteiro para um array de ponteiros para objetos ByteArray. Esse array representa uma
     * lista de CRLs (Listas de Revogação de Certificados).
     * @param crlListSize O parâmetro crlListSize representa o tamanho do array crlList.
     *
     * @return uma string que representa o horário da última atualização das CRLs
     * na lista fornecida.
     */
    char *getCrlUpdateInfoTime(ByteArray **crlList, size_t crlListSize)
    {
        const ASN1_TIME *updateTime = nullptr;

        // Itera sobre a lista de CRLs para encontrar a última data de atualização
        for (size_t i = 0; i < crlListSize; i++)
        {
            ByteArray *crlBytes = crlList[i];
            X509_CRL *crl = decodeCRLs(crlBytes);
            const ASN1_TIME *newUpdateTime = X509_CRL_get0_lastUpdate(crl);

            // Compara as datas de atualização e mantém a mais recente
            if (!updateTime || ASN1_TIME_compare(newUpdateTime, updateTime))
            {
                updateTime = newUpdateTime;
            }

            // Libera a memória da CRL
            X509_CRL_free(crl);
        }

        // Converte a data da última atualização para uma string legível
        char *updateTimeString = asn1_timeToString(updateTime);

        return updateTimeString;
    }

    /**
     * A função getCrlNextUpdateTime retorna uma representação de string do horário da próxima atualização de uma
     * Lista de Revogação de Certificados (CRL) de uma lista de CRLs.
     *
     * @param crlList Um ponteiro para um array de ponteiros para objetos ByteArray. Cada objeto ByteArray
     * representa uma Lista de Revogação de Certificados (CRL).
     * @param crlListSize O parâmetro crlListSize representa o tamanho do array crlList, que contém
     * ponteiros para objetos ByteArray.
     *
     * @return um ponteiro para um array de caracteres (string) que representa o horário da próxima atualização da
     * Lista de Revogação de Certificados (CRL).
     */
    char *getCrlNextUpdateTime(ByteArray **crlList, size_t crlListSize)
    {
        const ASN1_TIME *updateTime = nullptr;

        for (size_t i = 0; i < crlListSize; i++)
        {
            ByteArray *crlBytes = crlList[i];
            X509_CRL *crl = decodeCRLs(crlBytes);
            const ASN1_TIME *newUpdateTime = X509_CRL_get0_nextUpdate(crl);

            // if (!updateTime || ASN1_TIME_compare(newUpdateTime, updateTime) == -1) //MALWARE?
            if (!updateTime || ASN1_TIME_compare(newUpdateTime, updateTime))
            {
                updateTime = newUpdateTime;
            }

            X509_CRL_free(crl);
        }

        char *updateTimeString = asn1_timeToString(updateTime);

        return updateTimeString;
    }
    // Codigo Depreciado
    VerificationResponse do_verify_CMS(ByteArray *msg, ByteArray *sig)
    {
        VerificationResponse res;
        res.verificationType = "Offline";
        res.validChain = "Não Verificada";
        res.result = "Não foi possível verificar a assinatura digital. Tente novamente mais tarde.";
        res.code = 0;
        BIO *indata = BIO_new_mem_buf(msg->data, msg->len);
        unsigned int flags = CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY;
        int result = -1;

        BIO *sigBio = BIO_new_mem_buf(sig->data, sig->len);

        CMS_ContentInfo *cms = d2i_CMS_bio(sigBio, NULL);

        if (cms != NULL)
        {
            result = CMS_verify(cms, nullptr, nullptr, indata, nullptr, flags);
        }
        else
        {
            result = 0;
        }

        if (result == 1)
        {
            res.validChain = "Não verificada";
            res.signature = "Válida";
            res.result = "Sem conexão com o servidor. Não foi possível fazer a verificação completa da assinatura digital.";
            res.code = 2;
        }
        else
        {
            res.validChain = "Não verificada";
            res.signature = "Inválida";
            res.result = "Assinatura digital inválida.";
            res.code = 4;
        }

        BIO_free(indata);
        BIO_free(sigBio);
        CMS_ContentInfo_free(cms);

        return res;
    }

    char *do_verify_cert(ByteArray *targetCertPem, ByteArray **targetChainPem, size_t targetChainSize, ByteArray **trustedCertsPem, size_t trustedCertsSize)
    {
        char *ret;
        int rc;
        X509_STORE *store = nullptr;
        X509_STORE_CTX *cert_ctx = nullptr;
        STACK_OF(X509) *certs = nullptr;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /*instancia store de certificados
         * ignorou-se a possibilidade de falta de memoria
         */
        store = X509_STORE_new();

        /*instancia contexto
         * ignorou-se a possibilidade de falta de memoria
         */
        cert_ctx = X509_STORE_CTX_new();

        /*instancia pilha de certificados para conter caminho de certificacao
         * ignorou-se a possibilidade de falta de memoria
         */
        certs = sk_X509_new_null();

        // popula pilha
        for (size_t k = 0; k < targetChainSize; k++)
        {
            /* ignorou-se o retorno do push na pilha.
             * Retorno de erro (0) ocorreria no caso de falta de memoria.
             * Ver funcao sk_insert do openssl
             */
            ByteArray *encodedCert = targetChainPem[k];

            X509 *px = decode_x509(encodedCert);

            if (px != nullptr)
                sk_X509_push(certs, px);
        }

        // define funcao de callback
        // X509_STORE_set_verify_cb_func(store, CertPathValidator::callback);

        // define certificados confiaveis
        for (size_t i = 0; i < trustedCertsSize; i++)
        {
            ByteArray *pem = trustedCertsPem[i];
            X509 *teste = decode_x509(pem);
            X509_STORE_add_cert(store, teste);
            X509_free(teste);
        }

        /* inicializa contexto
         * ignorou-se a possibilidade de falta de memoria
         */
        X509 *targetX509 = decode_x509(targetCertPem);

        X509_STORE_CTX_init(cert_ctx, store, targetX509, certs);

        /* define a data para verificar os certificados da cadeia
         * obs: o segundo parametro da funcao
         * void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t)
         * nao eh utilizado, segundo verificou-se no arquivo crypto/x509/x509_vfy.c
         */
        // X509_STORE_CTX_set_time(cert_ctx, 0 ,this->when.getDateTime());

        /*Garante que não há informações de validações prévias*/
        // CertPathValidator::results.clear();

        /*verifica certificado*/
        if (X509_verify_cert(cert_ctx) == 1)
        {
            ret = "Válida";
        }
        else
        {
            // ret = (char *)X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx));
            // std::cout << X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)) << std::endl;
            ret = "Inválida";
        }

        /*desaloca estruturas*/
        sk_X509_pop_free(certs, X509_free);
        // sk_X509_free(certs);
        X509_free(targetX509);
        X509_STORE_free(store);
        X509_STORE_CTX_free(cert_ctx);
        return ret;
    }

    bool hasCert(ByteArray *cmsDer, ByteArray *certPem)
    {
        bool ret = false;
        X509 *signerCert = decode_x509(certPem);
        BIO *in = BIO_new_mem_buf(cmsDer->data, cmsDer->len);
        CMS_ContentInfo *cms = d2i_CMS_bio(in, nullptr);

        if (cms == nullptr || signerCert == nullptr)
        {
            return false;
        }

        STACK_OF(X509) *certs = CMS_get1_certs(cms);

        for (int i = 0; i < sk_X509_num(certs); i++)
        {
            X509 *aCert = sk_X509_pop(certs);
            if (X509_cmp(signerCert, aCert) == 0)
            {
                ret = true;
                X509_free(aCert);
                break;
            }
            X509_free(aCert);
        }

        X509_free(signerCert);
        // BIO_set_close(in, BIO_NOCLOSE);
        BIO_free(in);
        CMS_ContentInfo_free(cms);
        sk_X509_pop_free(certs, X509_free);

        return ret;
    }

    ByteArray *add_signer_cert(ByteArray *cmsDer, ByteArray *signerCertPem)
    {
        if (hasCert(cmsDer, signerCertPem))
            return nullptr;

        X509 *signerCert = decode_x509(signerCertPem);
        BIO *in = BIO_new_mem_buf(cmsDer->data, cmsDer->len);
        CMS_ContentInfo *cms = d2i_CMS_bio(in, nullptr);

        if (cms == nullptr || signerCert == nullptr)
        {
            return nullptr;
        }

        if (CMS_add0_cert(cms, signerCert) == 0) // adds cert internally to cms and it must not be freed up after the call
            return nullptr;

        BIO *out = BIO_new(BIO_s_mem());

        if (i2d_CMS_bio(out, cms) == 0)
            return nullptr;

        BUF_MEM *bptr;
        BIO_get_mem_ptr(out, &bptr);

        ByteArray *cmsDerWithCert = new ByteArray;
        cmsDerWithCert->len = bptr->length;
        cmsDerWithCert->data = new unsigned char[bptr->length];
        memcpy(cmsDerWithCert->data, bptr->data, bptr->length);

        BIO_free(out);
        BIO_free(in);
        CMS_ContentInfo_free(cms);

        return cmsDerWithCert;
    }

    char *get_crl_last_update_time(ByteArray **crlList, size_t crlListSize, ByteArray *cert)
    {
        char *ret = "Não foi possível obter a data de atualização da lista de revogação";
        if (crlList == nullptr)
            return ret;

        // verify if the crl is emited by the same CA that issued the certificate
        X509 *signerCert = decode_x509(cert);
        X509_NAME *subject = X509_get_subject_name(signerCert);

        for (unsigned int i = 0; i < crlListSize; i++)
        {
            ByteArray *pem = crlList[i];

            X509_CRL *crl = decode_crl(pem);

            X509_NAME *issuer = X509_CRL_get_issuer(crl);
            if (X509_NAME_cmp(issuer, subject) == 0)
            {
                const ASN1_TIME *time = X509_CRL_get0_lastUpdate(crl);

                BIO *bmem = BIO_new(BIO_s_mem());

                if (ASN1_TIME_print(bmem, time))
                {
                    BUF_MEM *bptr;

                    BIO_get_mem_ptr(bmem, &bptr);

                    ret = new char[bptr->length + 1];
                    memcpy(ret, bptr->data, bptr->length);
                    ret[bptr->length] = '\0';
                    BIO_free(bmem);
                }
            }

            X509_CRL_free(crl);
        }

        X509_free(signerCert);

        return ret;
    }

    char *get_crl_next_update_time(ByteArray **crlList, size_t crlListSize, ByteArray *cert)
    {
        char *ret = "Não foi possível obter a data de atualização da lista de revogação";
        if (crlList == nullptr)
            return ret;

        // verify if the crl is emited by the same CA that issued the certificate
        X509 *signerCert = decode_x509(cert);
        X509_NAME *subject = X509_get_subject_name(signerCert);

        for (unsigned int i = 0; i < crlListSize; i++)
        {
            ByteArray *pem = crlList[i];

            X509_CRL *crl = decode_crl(pem);

            X509_NAME *issuer = X509_CRL_get_issuer(crl);
            if (X509_NAME_cmp(issuer, subject) == 0)
            {
                const ASN1_TIME *time = X509_CRL_get0_nextUpdate(crl);

                BIO *bmem = BIO_new(BIO_s_mem());

                if (ASN1_TIME_print(bmem, time))
                {
                    BUF_MEM *bptr;

                    BIO_get_mem_ptr(bmem, &bptr);

                    ret = new char[bptr->length + 1];
                    memcpy(ret, bptr->data, bptr->length);
                    ret[bptr->length] = '\0';
                    BIO_free(bmem);
                }
            }

            X509_CRL_free(crl);
        }

        X509_free(signerCert);

        return ret;
    }

    char *do_verify_cert_expiration(ByteArray *certPem)
    {
        X509 *cert = decode_x509(certPem);

        int notBefore = X509_cmp_current_time(X509_get_notBefore(cert));
        int notAfter = X509_cmp_current_time(X509_get_notAfter(cert));

        // get in char format expiration date of the cert
        BIO *bmem = BIO_new(BIO_s_mem());
        ASN1_TIME *time = X509_get_notAfter(cert);
        ASN1_TIME_print(bmem, time);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bmem, &bptr);
        char *expirationDate = new char[bptr->length + 1];
        memcpy(expirationDate, bptr->data, bptr->length);
        expirationDate[bptr->length] = '\0';
        BIO_free(bmem);

        X509_free(cert);

        if ((notBefore < 1 && notAfter < 1))
        {
            char *ret = (char *)malloc(strlen(expirationDate) + strlen("|expirado") + 2);

            strcpy(ret, expirationDate);
            strcat(ret, "|expirado");

            return ret;
        }
        else
        {
            char *ret = (char *)malloc(strlen(expirationDate) + strlen("|valido") + 2);

            strcpy(ret, expirationDate);
            strcat(ret, "|valido");

            return ret;
        }
    }

    char *get_CN_and_serial(ByteArray *cert)
    {
        char *ret = "Não foi possível obter o CN e o serial do certificado";
        if (cert == nullptr)
            return ret;

        X509 *x509 = decode_x509(cert);

        if (x509 == nullptr)
            return ret;

        char *issuer_name = X509_NAME_oneline(X509_get_issuer_name(x509), 0, 0);
        char *subject_name = X509_NAME_oneline(X509_get_subject_name(x509), 0, 0);

        char *name = (char *)malloc(strlen(issuer_name) + strlen(subject_name) + 3);

        strcpy(name, issuer_name);
        strcat(name, "|");
        strcat(name, subject_name);

        X509_free(x509);
        return name;
    }

    char *do_verify_cert_with_crl(ByteArray *targetCertPem, ByteArray **targetChainPem, size_t targetChainSize, ByteArray **trustedCertsPem, size_t trustedCertsSize, ByteArray **crlsPem, size_t crlsSize)
    {
        if (targetCertPem == nullptr || targetChainPem == nullptr || trustedCertsPem == nullptr)
        {
            return "target certificate, target certificate chain, and trusted certificates cannot be null";
        }

        char *ret;
        int rc;
        X509_STORE *store = nullptr;
        X509_STORE_CTX *cert_ctx = nullptr;
        STACK_OF(X509) *certs = nullptr;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /*instancia store de certificados
         * ignorou-se a possibilidade de falta de memoria
         */
        store = X509_STORE_new();

        /*instancia contexto
         * ignorou-se a possibilidade de falta de memoria
         */
        cert_ctx = X509_STORE_CTX_new();

        /*instancia pilha de certificados para conter caminho de certificacao
         * ignorou-se a possibilidade de falta de memoria
         */
        certs = sk_X509_new_null();

        // popula pilha
        for (size_t k = 0; k < targetChainSize; k++)
        {
            /* ignorou-se o retorno do push na pilha.
             * Retorno de erro (0) ocorreria no caso de falta de memoria.
             * Ver funcao sk_insert do openssl
             */
            ByteArray *encodedCert = targetChainPem[k];

            X509 *px = decode_x509(encodedCert);

            if (px != nullptr)
                sk_X509_push(certs, px);
        }

        // define funcao de callback
        // X509_STORE_set_verify_cb_func(store, CertPathValidator::callback);

        // define certificados confiaveis
        for (size_t i = 0; i < trustedCertsSize; i++)
        {
            ByteArray *pem = trustedCertsPem[i];
            X509 *teste = decode_x509(pem);
            X509_STORE_add_cert(store, teste);
            X509_free(teste);
        }

        // adiciona se CRLs se disponiveis
        if (crlsPem != nullptr && crlsSize > 0)
        {
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);

            for (unsigned int i = 0; i < crlsSize; i++)
            {
                ByteArray *pem = crlsPem[i];

                X509_CRL *crl = decode_crl(pem);

                // X509_CRL *crl = pem2crl(pem);
                X509_STORE_add_crl(store, crl);
                X509_CRL_free(crl);
            }
        }

        /* inicializa contexto
         * ignorou-se a possibilidade de falta de memoria
         */
        X509 *targetX509 = decode_x509(targetCertPem);

        X509_STORE_CTX_init(cert_ctx, store, targetX509, certs);

        if (X509_verify_cert(cert_ctx) == 1)
        {
            ret = "Válida";
        }
        else
        {
            int err = X509_STORE_CTX_get_error(cert_ctx);

            char *name = X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(cert_ctx)), 0, 0);
            if (err == X509_V_ERR_CERT_REVOKED)
            {

                char *revoked_str = (char *)malloc(strlen(name) + strlen(":revogado") + 2);

                strcpy(revoked_str, name);
                strcat(revoked_str, ":revogado");

                ret = revoked_str;
            }
            else if (err == X509_V_ERR_CRL_HAS_EXPIRED || err == X509_V_ERR_CRL_NOT_YET_VALID)
            {
                char *crlExpirada_str = (char *)malloc(strlen(name) + strlen(":crlExpirada") + 2);

                strcpy(crlExpirada_str, name);
                strcat(crlExpirada_str, ":crlExpirada");

                ret = crlExpirada_str;
            }
            else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            {
                char *expirada_str = (char *)malloc(strlen(name) + strlen(":expirada") + 2);

                strcpy(expirada_str, name);
                strcat(expirada_str, ":expirada");

                ret = expirada_str;
            }
            else
            {
                char *invalid_str = (char *)malloc(strlen(name) + strlen(":invalid") + 2);

                strcpy(invalid_str, name);
                strcat(invalid_str, ":invalid");

                ret = invalid_str;
            }

            return ret;
            // std::cout << X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)) << std::endl;
        }

        /*desaloca estruturas*/
        sk_X509_pop_free(certs, X509_free);
        // sk_X509_free(certs);
        X509_free(targetX509);
        X509_STORE_free(store);
        X509_STORE_CTX_free(cert_ctx);
        return ret;
    }
    // FIM DO CÓDIGO DEPRECIADO
    /**
     * A função "numberOfDistributionPoints" retorna o número de URLs de distribuição em um
     * certificado X509 fornecido.
     *
     * @param cert Um ponteiro para um objeto X509.
     *
     * @return o número de URLs de distribuição encontradas no certificado X509 fornecido.
     */
    int numberOfDistributionPoints(ByteArray *cert)
    {
        int numberOfDistributionURLS = 0;
        int nid = NID_crl_distribution_points;
        X509 *certificate = decodeCertificate(cert);
        if (certificate == nullptr)
        {
            return -1;
        }
        STACK_OF(DIST_POINT) *distributionPoints = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(certificate, nid, nullptr, NULL);
        if (distributionPoints != nullptr)
        {
            numberOfDistributionURLS = sk_DIST_POINT_num(distributionPoints);
            sk_DIST_POINT_pop_free(distributionPoints, DIST_POINT_free);
        }
        X509_free(certificate);
        return numberOfDistributionURLS;
    }

    /**
     * A função getCrlDistribution recebe um certificado como entrada, decodifica-o, recupera os pontos de distribuição de CRL
     * e retorna um array de URLs.
     *
     * @param cert Um ponteiro para um objeto ByteArray que representa um certificado.
     *
     * @return um ponteiro para uma estrutura do tipo Links que contém os URLs dos pontos de distribuição de CRL.
     */
    Links *getCrlDistribution(ByteArray *cert)
    {
        // Verifica se o certificado de entrada é válido
        if (!cert)
        {
            return nullptr;
        }

        // Decodifica o certificado X.509
        X509 *certificate = decodeCertificate(cert);
        if (!certificate)
        {
            return nullptr;
        }

        // Identifica o NID para os pontos de distribuição de CRL
        int nid = NID_crl_distribution_points;

        // Obtém os pontos de distribuição de CRL do certificado
        auto distributionPoints = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(certificate, nid, nullptr, nullptr);

        // Verifica se os pontos de distribuição foram encontrados
        if (distributionPoints == nullptr)
        {
            X509_free(certificate);
            return nullptr;
        }

        // Obtém o número de pontos de distribuição
        int size = sk_DIST_POINT_num(distributionPoints);

        // Verifica se há pontos de distribuição de CRL
        if (size == 0)
        {
            X509_free(certificate);
            sk_DIST_POINT_pop_free(distributionPoints, DIST_POINT_free);
            return nullptr;
        }

        // Aloca memória para armazenar os URLs
        char **urls = new char *[size];
        int urlIndex = 0;

        // Itera sobre os pontos de distribuição
        for (int crlIndex = 0; crlIndex < size; crlIndex++)
        {
            DIST_POINT *dp = sk_DIST_POINT_value(distributionPoints, crlIndex);

            // Verifica se o ponto de distribuição é válido
            if (dp == nullptr || dp->distpoint == nullptr)
            {
                X509_free(certificate);
                sk_DIST_POINT_pop_free(distributionPoints, DIST_POINT_free);
                delete[] urls;
                return nullptr;
            }

            DIST_POINT_NAME *distpoint = dp->distpoint;
            int numNames = sk_GENERAL_NAME_num(distpoint->name.fullname);

            // Itera sobre os nomes de distribuição
            for (int k = 0; k < numNames; k++)
            {
                GENERAL_NAME *generalName = sk_GENERAL_NAME_value(distpoint->name.fullname, k);

                // Verifica se o nome é um URL
                if (generalName != nullptr && generalName->type == GEN_URI && generalName->d.uniformResourceIdentifier != nullptr)
                {
                    ASN1_IA5STRING *urlInASN1 = generalName->d.uniformResourceIdentifier;
                    auto *url = (char *)ASN1_STRING_get0_data(urlInASN1);
                    urls[urlIndex] = url;
                    urlIndex++;
                }
            }
        }

        // Libera a memória e retorna os URLs
        X509_free(certificate);
        sk_DIST_POINT_pop_free(distributionPoints, DIST_POINT_free);
        auto urlLinks = new Links{urls, urlIndex};
        return urlLinks;
    }

    /**
     * A função verifica se uma cadeia de certificados foi revogada, verificando-a em relação a uma lista de Listas de Revogação de Certificados (CRLs)
     * e certificados intermediários.
     *
     * @param endCertificate Um ponteiro para um certificado X509 que representa o certificado final na cadeia.
     * @param crls Um array de ponteiros para objetos ByteArray que representam as Listas de Revogação de Certificados (CRLs) a serem verificadas quanto ao status de revogação.
     * @param crlSize O número de Listas de Revogação de Certificados (CRLs) fornecidas como entrada para a função.
     * @param intermediaryCerts Uma pilha de certificados X509 que representa os certificados intermediários na cadeia de certificados.
     *
     * @return um valor booleano que indica se o certificado final na cadeia foi revogado ou não.
     */
    bool isChainRevoked(X509 *endCertificate, ByteArray **crls, size_t crlSize, STACK_OF(X509) * intermediaryCerts)
    {
        bool isRevoked = false;
        X509_CRL *decodedCrl = nullptr;

        // Itera sobre os certificados intermediários na pilha
        for (size_t i = 0; i < sk_X509_num(intermediaryCerts) - 1; i++)
        {
            X509 *issuerCert = sk_X509_value(intermediaryCerts, i);

            // Verifica se o certificado do emissor e o certificado final são válidos
            if (issuerCert && endCertificate)
            {
                // Obtém a chave pública do emissor
                EVP_PKEY *issuerKey = X509_get_pubkey(issuerCert);
                ASN1_INTEGER *serial = X509_get_serialNumber(endCertificate);

                // Itera sobre as Listas de Revogação de Certificados (CRLs)
                for (size_t j = 0; j < crlSize - 1; j++)
                {
                    // Decodifica a CRL
                    decodedCrl = decodeCRLs(crls[j]);

                    // Verifica a revogação usando a chave do emissor
                    int revocationCheck = X509_CRL_verify(decodedCrl, issuerKey);
                    X509_CRL_free(decodedCrl);

                    // Se o certificado final estiver revogado, retorna verdadeiro
                    if (revocationCheck == 1)
                    {
                        X509_REVOKED *revoked = nullptr;
                        return X509_CRL_get0_by_serial(decodedCrl, &revoked, serial) == 1;
                    }
                }
                // Define o certificado do emissor como o certificado final para a próxima iteração
                endCertificate = issuerCert;
            }
        }
        return isRevoked;
    }

    char *getOpenSSLVersion()
    {
        return OPENSSL_VERSION_TEXT;
    }

    /**
     * A função "cleanup" libera a memória de certificados X509 e estruturas relacionadas.
     *
     * @param targetX509Cert Um ponteiro para o certificado X509 que precisa ser liberado.
     * @param intermediaryCertsStack Uma pilha de certificados X509 que são usados como intermediários na
     * cadeia de certificados.
     * @param trustedStore Um ponteiro para um objeto X509_STORE, que representa uma coleção de certificados confiáveis.
     * Esta loja é usada para verificação de certificados.
     * @param certVerificationStructure O parâmetro certVerificationStructure é um ponteiro para uma estrutura
     * que contém o contexto para verificação de certificados. É usado pelas funções de verificação de certificados X509
     * para armazenar e recuperar informações sobre o processo de verificação.
     */
    void cleanup(X509 *targetX509Cert, STACK_OF(X509) * intermediaryCertsStack, X509_STORE *trustedStore, X509_STORE_CTX *certVerificationStructure)
    {
        if (intermediaryCertsStack)
            sk_X509_pop_free(intermediaryCertsStack, X509_free);
        if (targetX509Cert)
            X509_free(targetX509Cert);
        if (trustedStore)
            X509_STORE_free(trustedStore);
        if (certVerificationStructure)
            X509_STORE_CTX_free(certVerificationStructure);
    }

    /**
     * A função "identifyCause" recebe um código de erro como entrada e retorna uma mensagem de erro
     * correspondente.
     *
     * @param errorCode O parâmetro errorCode é um inteiro que representa o código de erro.
     *
     * @return A função identifyCause retorna um char* (ponteiro para um caractere) que representa
     * a causa do código de erro fornecido.
     */
    char *identifyCause(int errorCode)
    {
        switch (errorCode)
        {
        case X509_V_ERR_OCSP_VERIFY_FAILED:
            return "Verificacao de OCSP (CRL) falhou";
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "Algum dos certificados da cadeia esta expirado";
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "Algum dos certificados da cadeia ainda nao é valido";
            break;
        case X509_V_ERR_CERT_REVOKED:
            return "Algum dos certificados da cadeia esta revogado";
            break;
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return "Alguma das CRLs esta expirada";
            break;
        case X509_V_ERR_CRL_NOT_YET_VALID:
            return "Alguma das CRLs ainda nao é valida";
            break;
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            return "Falha na verificacao da assinatura de uma das CRLs";
            break;
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return "Falha na verificacao da assinatura de um dos certificados";
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            return "Nao foi possivel obter o certificado do emissor";
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return "Nao foi possivel obter a CRL";
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            return "Nao foi possivel descriptografar a assinatura do certificado";
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            return "Nao foi possivel descriptografar a assinatura da CRL";
            break;
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            return "Nao foi possivel decodificar a chave publica do emissor";
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "Nao foi possivel obter o certificado do emissor localmente";
            break;
        case X509_V_ERR_CERT_UNTRUSTED:
            return "Certificado nao confiavel";
            break;
        case X509_V_ERR_CERT_REJECTED:
            return "Certificado rejeitado";
            break;
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            return "Certificado nao pode ser usado para assinar outros certificados";
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            return "Nao foi possivel obter o emissor da CRL";
            break;
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            return "Extensao critica nao tratada";
            break;
        default:
            return "Falha ao decodificar error";
            break;
        }
    }

    /**
     * A função verifyCertificateChain verifica a validade de uma cadeia de certificados usando a biblioteca OpenSSL em C++.
     *
     * @param endCertificate Um ponteiro para um objeto ByteArray que representa o certificado final a ser verificado.
     * @param certificateChain Um array de ponteiros para objetos ByteArray que representam os certificados intermediários na cadeia de certificados.
     * @param chainSize O número de certificados na cadeia de certificados.
     * @param crlsCertificates Um array de certificados CRL (Lista de Revogação de Certificados) usados para verificar o status de revogação dos certificados na cadeia.
     * @param crlSize O número de CRLs (Listas de Revogação de Certificados) no array crlsCertificates.
     * @param trustedCertificates Um array de certificados confiáveis usados para verificar a cadeia de certificados.
     * @param trustedCertificatesSize O número de certificados confiáveis no array trustedCertificates.
     *
     * @return um objeto Response indicando se a cadeia de certificados é válida.
     */
    Response verifyCertificateChain(
        ByteArray *endCertificate,
        ByteArray **certificateChain,
        size_t chainSize,
        ByteArray **crlsCertificates,
        size_t crlSize,
        ByteArray **trustedCertificates,
        size_t trustedCertificatesSize)
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        X509 *targetX509Cert = nullptr;
        STACK_OF(X509) *intermediaryCertsStack = nullptr;
        X509_STORE *trustedStore = nullptr;
        X509_STORE_CTX *certVerificationStructure = nullptr;

        // Verifica a presença de dados de entrada válidos
        if (!endCertificate || !certificateChain || !trustedCertificates || chainSize == 0)
        {
            return Response{
                false,
                "Certificado ou cadeia de certificados ausente(s)"};
        }

        // Decodifica o certificado final
        targetX509Cert = decodeCertificate(endCertificate);

        if (!targetX509Cert)
        {
            return Response{
                false,
                "Falha na decodificação do certificado final"};
        }

        // Inicializa a pilha de certificados intermediários
        intermediaryCertsStack = sk_X509_new_null();
        if (!intermediaryCertsStack)
        {
            cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
            return Response{
                false,
                "Falha na criação da pilha de certificados intermediários"};
        }

        // Adiciona os certificados intermediários à pilha
        if (!addCertificatesToStack(certificateChain, chainSize, intermediaryCertsStack))
        {
            cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
            return Response{
                false,
                "Falha na adição de certificados intermediários à pilha"};
        }

        // Cria o armazenamento de certificados confiáveis
        trustedStore = X509_STORE_new();
        if (!trustedStore)
        {
            cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
            return Response{
                false,
                "Falha na criação do armazenamento de certificados confiáveis"};
        }

        X509 *trustedCert = nullptr;

        // Decodifica e adiciona certificados confiáveis ao armazenamento
        for (size_t y = 0; y < trustedCertificatesSize; y++)
        {
            if (trustedCertificates[y] == nullptr || trustedCertificates[y]->data == nullptr || trustedCertificates[y]->len <= 0)
            {
                cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
                return Response{
                    false,
                    "Falha na decodificação do certificado raiz"};
            }

            trustedCert = decodeCertificate(trustedCertificates[y]);

            if (!trustedCert)
            {
                cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
                return Response{
                    false,
                    "Falha na decodificação do certificado raiz"};
            }

            X509_STORE_add_cert(trustedStore, trustedCert);
        }

        // Define as flags para verificar CRLs
        X509_STORE_set_flags(trustedStore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

        // Adiciona CRLs ao armazenamento
        if (crlSize > 0)
        {
            addCrlsToStore(crlsCertificates, crlSize, trustedStore);
        }

        certVerificationStructure = X509_STORE_CTX_new();

        if (!certVerificationStructure)
        {
            cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);
            return Response{
                false,
                "Falha na inicialização da estrutura de verificação de certificados"};
        }

        // Inicializa a estrutura de verificação de certificados
        X509_STORE_CTX_init(certVerificationStructure, trustedStore, targetX509Cert, intermediaryCertsStack);

        int verifyResult = X509_verify_cert(certVerificationStructure);
        Response verificationResponse;

        if (verifyResult == 1)
        {
            verificationResponse.isValid = true;
            verificationResponse.response = "Cadeia de certificados válida";
        }
        else if (verifyResult == 0)
        {
            verificationResponse.isValid = false;
            verificationResponse.response = identifyCause(X509_STORE_CTX_get_error(certVerificationStructure));
        }
        else // verifyResult <  0
        {
            verificationResponse.isValid = false;
            verificationResponse.response = "Falha ao verificar a cadeia";
        }

        // Libera memória e retorna a resposta de verificação
        cleanup(targetX509Cert, intermediaryCertsStack, trustedStore, certVerificationStructure);

        return verificationResponse;
    }

    /**
     * Decodifica uma cadeia de certificados PKCS7 de um ByteArray.
     *
     * @param certificateChain um ponteiro para o ByteArray contendo a cadeia de certificados
     *
     * @return um ponteiro para a cadeia de certificados PKCS7 decodificada
     *
     * @throws None
     */
    PKCS7 *decodeP7B(const ByteArray *certificateChain)
    {
        PKCS7 *p7bChain = nullptr;
        BIO *p7bInputBio = nullptr;
        // Cria um objeto BIO para ler a cadeia de certificados a partir de um buffer de memória

        p7bInputBio = BIO_new_mem_buf(certificateChain->data, certificateChain->len);
        // Verifica se o objeto BIO foi criado com sucesso

        if (p7bInputBio != nullptr)
        {
            // Tenta decodificar a cadeia de certificados no formato PEM

            if (PEM_read_bio_PKCS7(p7bInputBio, &p7bChain, nullptr, nullptr) == nullptr)
            {
                // Falha na decodificação como PEM, tenta o formato DER
                BIO_reset(p7bInputBio);
                if (d2i_PKCS7_bio(p7bInputBio, &p7bChain) == nullptr)
                {
                    // Falha na decodificação como DER também
                    return nullptr;
                }
            }
            BIO_free(p7bInputBio);
        }
        // Retorna a cadeia de certificados PKCS7 decodificada

        return p7bChain;
    }

    /**
     * Decodifica uma cadeia de certificados PKCS7 contida em um ByteArray e extrai os certificados individuais.
     *
     * @param p7bCertificateChain Um ponteiro para o ByteArray que contém a cadeia de certificados PKCS7.
     *
     * @return Um ponteiro para um objeto ChainByteArrays que contém os certificados individuais, incluindo o certificado final,
     *         o certificado intermediário e o certificado raiz, se disponíveis. Retorna nullptr em caso de erro.
     *
     * @throws None
     */
    ChainByteArrays *decodeCertificateChain(const ByteArray *p7bCertificateChain)
    {
        PKCS7 *p7bChain = nullptr;                  // Inicializa o ponteiro p7bChain com a cadeia de certificados PKCS7
        ChainByteArrays *chainByteArrays = nullptr; // Inicializa o ponteiro chainByteArrays para armazenar os resultados
        STACK_OF(X509) *certs = nullptr;            // Inicializa o ponteiro certs para armazenar os certificados X509 da cadeia
        ByteArray *certificate = nullptr;           // Inicializa o ponteiro certificate para representar um certificado X509

        p7bChain = decodeP7B(p7bCertificateChain); // Decodifica o p7bCertificateChain usando a função decodeP7B

        if (!p7bChain)
        {
            return nullptr;
        }

        int ObjectIdentifier = OBJ_obj2nid(p7bChain->type); // Obtém o Identificador de Objeto da p7bChain

        // Verifica o Identificador de Objeto (Object Identifier) e define "certs" com base no tipo de certificado PKCS7.
        if (ObjectIdentifier == NID_pkcs7_signed)
        {
            certs = p7bChain->d.sign->cert; // Se o Identificador de Objeto for NID_pkcs7_signed, atribui "certs" aos certificados da cadeia.
        }
        else if (ObjectIdentifier == NID_pkcs7_signedAndEnveloped)
        {
            certs = p7bChain->d.signed_and_enveloped->cert; // Se o Identificador de Objeto for NID_pkcs7_signedAndEnveloped, atribui "certs" aos certificados da cadeia.
        }
        else
        {
            PKCS7_free(p7bChain); // Limpa o objeto PKCS7 se o Identificador de Objeto não for reconhecido
            return nullptr;
        }

        chainByteArrays = new ChainByteArrays;              // Cria um objeto ChainByteArrays para armazenar os certificados
        chainByteArrays->endCertificate = nullptr;          // Inicializa o ponteiro endCertificate como nulo
        chainByteArrays->intermediaryCertificate = nullptr; // Inicializa o ponteiro intermediaryCertificate como nulo
        chainByteArrays->rootCertificate = nullptr;         // Inicializa o ponteiro rootCertificate como nulo
        BIO *out;                                           // Inicializa o ponteiro "out" para manipular os dados do certificado

        for (int i = 0; certs && i < sk_X509_num(certs); i++)
        {                                                       // Itera através de cada certificado em "certs"
            X509 *decodedCertificate = sk_X509_value(certs, i); // Obtém o certificado decodificado de "certs" no índice i
            out = BIO_new(BIO_s_mem());                         // Cria um novo objeto BIO de memória

            if (i2d_X509_bio(out, decodedCertificate) == 0)
            {
                cleanup(decodedCertificate, nullptr, nullptr, nullptr);
                BIO_free(out);
                PKCS7_free(p7bChain);
                delete chainByteArrays;
                return nullptr; // Se houver erro na conversão do certificado decodificado para BIO, retorne nullptr
            }
            BUF_MEM *bptr;
            BIO_get_mem_ptr(out, &bptr);

            certificate = new ByteArray;                         // Cria um novo objeto ByteArray para representar o certificado
            certificate->len = bptr->length;                     // Define o comprimento do certificado
            certificate->data = new unsigned char[bptr->length]; // Aloca memória para os dados do certificado
            memcpy(certificate->data, bptr->data, bptr->length); // Copia os dados do certificado para o objeto ByteArray

            // Determina a posição do certificado na cadeia com base no índice "i".
            if (i == 0)
            {
                chainByteArrays->endCertificate = certificate; // Se o índice for 0, define endCertificate como o certificado
            }
            else if (i == 1)
            {
                chainByteArrays->intermediaryCertificate = certificate; // Se o índice for 1, define intermediaryCertificate como o certificado
            }
            else if (i == 2)
            {
                chainByteArrays->rootCertificate = certificate; // Se o índice for 2, define rootCertificate como o certificado raiz
            }

            BIO_free(out);
            cleanup(decodedCertificate, nullptr, nullptr, nullptr);
        }

        PKCS7_free(p7bChain);

        return chainByteArrays;
    }

    /**
     * Initializes the CrlUpdateInfo struct with the given parameters.
     *
     * @param crl pointer to CrlUpdateInfo struct
     * @param last string containing last update information
     * @param next string containing next update information
     * @param expired boolean indicating if the update is expired
     * @param error boolean indicating if there was an error
     *
     * @return void
     *
     * @throws None
     */
    void CrlUpdateInfo_Init(CrlUpdateInfo *crl, const char *last, const char *next, bool expired, bool error)
    {
        if (last != NULL)
        {
            crl->lastUpdate = strdup(last);
        }
        else
        {
            crl->lastUpdate = NULL;
        }

        if (next != NULL)
        {
            crl->nextUpdate = strdup(next);
        }
        else
        {
            crl->nextUpdate = NULL;
        }

        crl->isExpired = expired;
        crl->errorStatus = error;
    }

    /**
     * Cleans up the CrlUpdateInfo structure by freeing memory allocated for lastUpdate and nextUpdate.
     *
     * @param crl pointer to CrlUpdateInfo structure
     *
     * @return void
     *
     * @throws None
     */
    void CrlUpdateInfo_Cleanup(CrlUpdateInfo *crl)
    {
        free(crl->lastUpdate);
        free(crl->nextUpdate);
    }

    /**
     * Retrieves update information from the provided CRL.
     *
     * @param crl Pointer to the ByteArray containing the CRL
     *
     * @return CrlUpdateInfo containing the update information
     *
     * @throws std::exception if an error occurs during the process
     */
    CrlUpdateInfo getUpdateFromCrl(ByteArray *crl)
    {
        CrlUpdateInfo crlDateInformation;
        CrlUpdateInfo_Init(&crlDateInformation, NULL, NULL, false, true);
        X509_CRL *decodedCrl;

        try
        {

            decodedCrl = decodeCRLs(crl);

            crlDateInformation.lastUpdate = "Indeterminado";
            crlDateInformation.nextUpdate = "Indeterminado";

            if (!decodedCrl)
            {

                return crlDateInformation;
            }

            const ASN1_TIME *lastUpdate = X509_CRL_get0_lastUpdate(decodedCrl);
            const ASN1_TIME *nextUpdate = X509_CRL_get0_nextUpdate(decodedCrl);

            // Verifica se as datas da CRL são válidas
            if (
                lastUpdate != NULL && nextUpdate != NULL)
            {
                crlDateInformation.errorStatus = false;
                crlDateInformation.lastUpdate = asn1_timeToString(lastUpdate);
                crlDateInformation.nextUpdate = asn1_timeToString(nextUpdate);
                crlDateInformation.isExpired = isCrlExpired(nextUpdate);
            }
        }
        catch (const std::exception &e)
        {

            crlDateInformation.errorStatus = true;
        }

        if (decodedCrl)
        {
            X509_CRL_free(decodedCrl);
        }
        return crlDateInformation;
    }
}
#endif /* E2EED740_BB73_4E5B_8AEF_DA39A6F50E32 */
