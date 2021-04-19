package com.elisongomes;

import java.io.*;
import java.net.URL;
import java.nio.file.*;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.json.simple.JSONObject;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class PDFSignatureInfoParser {

    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private static String inFile = "";
    private static String outFile = "";
    private static String outJson = "";

    /**
     * This is the entry point for the application.
     *
     * @param args The command-line arguments.
     * @throws IOException                            If there is an error reading the file.
     * @throws CertificateException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.SignatureException
     */
    public static void main(String[] args)
            throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidNameException, OperatorCreationException, CMSException {

        if ((args.length < 2) || (args.length == 4 && !args[2].equals("-outfile")) || (args.length == 6 && !args[4].equals("-outjson"))
        ) {
            usage();
            System.exit(0);
        } else if (!args[0].equals("-infile")) {
            usage();
            System.exit(0);
        }

        inFile = args[1];
        outFile = args.length >= 4 ? args[3] : "";
        outJson = args.length == 6 ? args[5] : "";

        PDFSignatureInfoParser psip = new PDFSignatureInfoParser();
        psip.parserFile();
    }

    private static byte[] getbyteArray(InputStream is)
            throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int len;
        while ((len = is.read(buffer)) > -1) {
            baos.write(buffer, 0, len);
        }
        baos.flush();

        return baos.toByteArray();
    }

    public static void parserFile()
            throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidNameException, OperatorCreationException, CMSException {
        boolean success = true;
        String message = "";
        List<PDFSignatureInfo> lpsi = null;
        /*
         * --------------------------------------------------------------------
         * Verifica tipo do arquivo assinado
         * --------------------------------------------------------------------
         */
        String extension = "";
        int i = inFile.lastIndexOf(".");
        if (i > 0) {
            extension = inFile.toLowerCase().substring(i + 1);
        }
        if (extension.equals("pdf")) {
            lpsi = getPDFSignatureInfo(new FileInputStream(inFile));
            if (!outFile.isBlank()) {
                try {
                    Files.copy(Paths.get(inFile), Paths.get(outFile), StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                    message = e.getMessage();
                    success = false;
                }
            }
        } else if (extension.equals("p7s")) {
            lpsi = getP7SSignatureInfo(new FileInputStream(inFile));
        } else {
            message = "Extensão inválida.";
            success = false;
        }

        JSONObject jsObj = new JSONObject();
        if (lpsi != null) {
            List jsList = new LinkedList();
            for (PDFSignatureInfo psi : lpsi) {
                Map jsMap = new LinkedHashMap();
                /*
                 * --------------------------------------------------------------------
                 * Nome emissor
                 * --------------------------------------------------------------------
                 */
                jsMap.put("issuerName", psi.name);
                /*
                 * --------------------------------------------------------------------
                 * Quem assinou
                 * --------------------------------------------------------------------
                 */
                jsMap.put("subjectName", psi.contactInfo);

                /*
                 * --------------------------------------------------------------------
                 * Algoritmo usado na assinatura
                 * --------------------------------------------------------------------
                 */
                jsMap.put("algorithm", psi.certificateInfo.signAlgorithm);

                /*
                 * --------------------------------------------------------------------
                 * Data de assinatura
                 * --------------------------------------------------------------------
                 */
                jsMap.put("signingTime", sdf.format(psi.signDate));
                /*
                 * --------------------------------------------------------------------
                 * Validade - Início
                 * --------------------------------------------------------------------
                 */
                jsMap.put("notBefore", sdf.format(psi.certificateInfo.notValidBefore));
                /*
                 * --------------------------------------------------------------------
                 * Validade - Fim
                 * --------------------------------------------------------------------
                 */
                jsMap.put("notAfter", sdf.format(psi.certificateInfo.notValidAfter));
                /*
                 * --------------------------------------------------------------------
                 * Extensões
                 * --------------------------------------------------------------------
                 */
                jsMap.put("subjectAlternativeName", psi.alternativeName);
                /*
                 * --------------------------------------------------------------------
                 * Verifica validade
                 * --------------------------------------------------------------------
                 */
                jsMap.put("verified", psi.signatureVerified.equals("YES") ? 1 : 0);


                jsList.add(jsMap);
            }
            jsObj.put("signers", jsList);
        }
        jsObj.put("success", success ? 1 : 0);
        if (!success) {
            jsObj.put("message", message);
        }
        /*
         * --------------------------------------------------------------------
         * Gera arquivo JSON com dados
         * --------------------------------------------------------------------
         */
        if (!outJson.isBlank()) {
            try {
                FileWriter file = new FileWriter(outJson);
                file.write(jsObj.toJSONString());
                file.flush();
                file.close();
            } catch (IOException e) {
                jsObj.put("success", 0);
                jsObj.put("message", e.getMessage());
            }
        }
        System.out.println(jsObj.toJSONString());
    }

    public static List<PDFSignatureInfo> getP7SSignatureInfo(InputStream is)
            throws IOException, CMSException, InvalidNameException, CertificateException, NoSuchAlgorithmException,
            OperatorCreationException, NoSuchProviderException {

        byte[] byteArray = getbyteArray(is);
        return getP7SSignatureInfo(byteArray);
    }

    public static List<PDFSignatureInfo> getP7SSignatureInfo(byte[] byteArray)
            throws CMSException, InvalidNameException, CertificateException, NoSuchAlgorithmException,
            IOException, OperatorCreationException, NoSuchProviderException {
        List<PDFSignatureInfo> lpsi = new ArrayList<PDFSignatureInfo>();

        PDFSignatureInfo psi = new PDFSignatureInfo();
        lpsi.add(psi);

        CMSSignedData sid = new CMSSignedData(byteArray);

        /*
         * --------------------------------------------------------------------
         * Extrair arquivo PDF
         * --------------------------------------------------------------------
         */
        if (!outFile.isBlank()) {
            sid.getSignedContent().write(new FileOutputStream(outFile));
        }

        // download the signed content
        byte[] buf;
        buf = (byte[]) sid.getSignedContent().getContent();
        verifyPKCS7(sid, psi);

        return lpsi;
    }

    public static List<PDFSignatureInfo> getPDFSignatureInfo(InputStream is) throws IOException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidNameException {

        byte[] byteArray = getbyteArray(is);
        return getPDFSignatureInfo(byteArray);
    }

    public static List<PDFSignatureInfo> getPDFSignatureInfo(byte[] byteArray) throws IOException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidNameException {

        List<PDFSignatureInfo> lpsi = new ArrayList<PDFSignatureInfo>();

        // Try to open the input file as PDF
        try (PDDocument document = PDDocument.load(new ByteArrayInputStream(byteArray))) {
            // Get Signature dictionaries of PDF
            for (PDSignature sig : document.getSignatureDictionaries()) {
                PDFSignatureInfo psi = new PDFSignatureInfo();
                lpsi.add(psi);

                COSDictionary sigDict = sig.getCOSObject();
                COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

                Set<Map.Entry<COSName, COSBase>> entries = sigDict.entrySet();
                for (Map.Entry<COSName, COSBase> entry : entries) {
                    // Don't return contents
                    if (!entry.getKey().equals(COSName.CONTENTS)) {
                        psi.entries.put(entry.getKey().getName(), entry.getValue().toString());
                    }
                }

                psi.reason = sig.getReason();
                psi.fullName = sig.getName();
                psi.signDate = sig.getSignDate().getTime();
                psi.subFilter = sig.getSubFilter();
                psi.fullContactInfo = sig.getContactInfo();
                psi.filter = sig.getFilter();
                psi.location = sig.getLocation();

                byte[] buf;
                buf = sig.getSignedContent(new ByteArrayInputStream(byteArray));

                int[] byteRange = sig.getByteRange();
                if (byteRange.length != 4) {
                    throw new IOException("Signature byteRange must have 4 items");
                } else {
                    long fileLen = byteArray.length;
                    long rangeMax = byteRange[2] + (long) byteRange[3];
                    // multiply content length with 2 (because it is in hex in the PDF) and add 2 for < and >
                    int contentLen = sigDict.getString(COSName.CONTENTS).length() * 2 + 2;
                    if (fileLen != rangeMax || byteRange[0] != 0 || byteRange[1] + contentLen != byteRange[2]) {
                        // a false result doesn't necessarily mean that the PDF is a fake
                        // System.out.println("Signature does not cover whole document");
                        psi.coversWholeDocument = false;
                    } else {
                        //System.out.println("Signature covers whole document");
                        psi.coversWholeDocument = true;
                    }
                }

                String subFilter = sig.getSubFilter();
                if (subFilter != null) {
                    switch (subFilter) {
                        case "adbe.pkcs7.detached":
                            verifyPKCS7(getSignedData(buf, contents), sig, psi);

                            //TODO check certificate chain, revocation lists, timestamp...
                            break;
                        case "adbe.pkcs7.sha1": {
                            // example: PDFBOX-1452.pdf
                            COSString certString = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
                            byte[] certData = certString.getBytes();
                            CertificateFactory factory = CertificateFactory.getInstance("X.509");
                            ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                            Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                            //System.out.println("certs=" + certs);
                            byte[] hash = MessageDigest.getInstance("SHA1").digest(buf);
                            verifyPKCS7(getSignedData(hash, contents), sig, psi);

                            //TODO check certificate chain, revocation lists, timestamp...
                            break;
                        }
                        case "adbe.x509.rsa_sha1": {
                            // example: PDFBOX-2693.pdf
                            COSString certString = (COSString) sigDict.getDictionaryObject(COSName.getPDFName("Cert"));
                            byte[] certData = certString.getBytes();
                            CertificateFactory factory = CertificateFactory.getInstance("X.509");
                            ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                            Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                            //System.out.println("certs=" + certs);

                            //TODO verify signature
                            psi.signatureVerified = "Unable to verify adbe.x509.rsa_sha1 subfilter";
                            break;
                        }
                        default:
                            throw new IOException("Unknown certificate type " + subFilter);

                    }
                } else {
                    throw new IOException("Missing subfilter for cert dictionary");
                }
            }
        } catch (CMSException | OperatorCreationException ex) {
            throw new IOException(ex);
        }

        return lpsi;
    }


    /**
     * @param byteArray the byte sequence that has been signed
     * @param contents  the /Contents field as a COSString
     * @return
     * @throws CMSException
     */
    private static CMSSignedData getSignedData(byte[] byteArray, COSString contents)
            throws CMSException {
        CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
        CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());

        return signedData;
    }

    private static void verifyPKCS7(CMSSignedData sid, PDFSignatureInfo psi)
            throws InvalidNameException, CertificateException, NoSuchAlgorithmException, IOException,
            OperatorCreationException, NoSuchProviderException, CMSException {
        verifyPKCS7(sid, null, psi);
    }

    /**
     * Verify a PKCS7 signature.
     *
     * @param sid CMSSignedData
     * @param sig the PDF signature (the /V dictionary)
     * @param psi PDFSignatureInfo
     * @throws CMSException
     * @throws CertificateException
     * @throws StoreException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidNameException
     * @throws IOException
     */

    private static void verifyPKCS7(CMSSignedData sid, PDSignature sig, PDFSignatureInfo psi)
            throws CMSException, CertificateException, StoreException, OperatorCreationException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidNameException, IOException {

        Store certificatesStore = sid.getCertificates();
        Collection<SignerInformation> signers = sid.getSignerInfos().getSigners();
        SignerInformation signerInformation = signers.iterator().next();
        Collection matches = certificatesStore.getMatches(signerInformation.getSID());
        X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
        X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);

        /*
         * --------------------------------------------------------------------
         * Nome emissor
         *
         * O `sig.getName();` usado anteriormante retorna a entrada completa,
         * abaixo pego somente o `AC`
         * --------------------------------------------------------------------
         */
        psi.name = IETFUtils.valueToString(certificateHolder.getIssuer().getRDNs(BCStyle.CN)[0].getFirst().getValue());

        /*
         * --------------------------------------------------------------------
         * Quem assinou
         *
         * O `sig.getName();` usado anteriormante retorna a entrada completa,
         * abaixo pego somente o `AC`
         * --------------------------------------------------------------------
         */
        psi.contactInfo = IETFUtils.valueToString(certificateHolder.getSubject()
                .getRDNs(BCStyle.CN)[0].getFirst().getValue());

        /*
         * --------------------------------------------------------------------
         * Data de assinatura
         * --------------------------------------------------------------------
         */
        AttributeTable signedAttributesTable = signerInformation.getSignedAttributes();
        if (signedAttributesTable != null) {
            try {
                psi.signDate = (new DERUTCTime(signedAttributesTable.get(CMSAttributes.signingTime)
                        .getAttrValues().getObjectAt(0).toString()).getDate());
            } catch (Exception ex) {

            }
        }

        /*
         * --------------------------------------------------------------------
         * Extensões
         * --------------------------------------------------------------------
         */
        org.bouncycastle.asn1.x509.Extension subjectAlternativeName = certificateHolder
                .getExtension(X509Extensions.SubjectAlternativeName);
        if (subjectAlternativeName != null) {
            ASN1InputStream ais = new ASN1InputStream(certificateHolder.getExtension(X509Extensions.SubjectAlternativeName)
                    .getExtnValue().getOctetStream());
            ASN1Sequence seq = (ASN1Sequence) ais.readObject();
            GeneralName generalName;
            Enumeration<?> sit = seq.getObjects();
            while (sit.hasMoreElements()) {
                generalName = GeneralName.getInstance(sit.nextElement());
                if (generalName.getTagNo() == GeneralName.rfc822Name) {
                    psi.alternativeName = IETFUtils.valueToString(generalName.getName());
                }
            }
        }

        CertificateInfo ci = new CertificateInfo();
        psi.certificateInfo = ci;
        ci.issuerDN = certFromSignedData.getIssuerDN().toString();
        ci.subjectDN = certFromSignedData.getSubjectDN().toString();

        ci.notValidAfter = certFromSignedData.getNotAfter();
        ci.notValidBefore = certFromSignedData.getNotBefore();

        ci.signAlgorithm = certFromSignedData.getSigAlgName();
        ci.serial = certFromSignedData.getSerialNumber().toString();

        LdapName ldapDN = new LdapName(ci.issuerDN);
        for (Rdn rdn : ldapDN.getRdns()) {
            ci.issuerOIDs.put(rdn.getType(), rdn.getValue().toString());
        }

        ldapDN = new LdapName(ci.subjectDN);
        for (Rdn rdn : ldapDN.getRdns()) {
            ci.subjectOIDs.put(rdn.getType(), rdn.getValue().toString());
        }

        if (sig != null) {
            certFromSignedData.checkValidity(sig.getSignDate().getTime());
        }

        if (isSelfSigned(certFromSignedData)) {
            psi.isSelfSigned = true;
        } else {
            psi.isSelfSigned = false;
        }

        if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certFromSignedData))) {
            //Signature verified
            psi.signatureVerified = "YES";
        } else {
            //Signature verification failed
            psi.signatureVerified = "NO";
        }
    }

    /**
     * Checks whether given X.509 certificate is self-signed.
     */
    private static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException sigEx) {
            return false;
        }
    }

    private static boolean isRevoked(Certificate cert) throws CertificateException, IOException, CRLException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String crlURLString = "http://crl.ermis.gov.gr/HPARCAPServants/LatestCRL.crl";
        URL crlURL = new URL(crlURLString);
        InputStream crlStream = crlURL.openStream();
        X509CRL crl = (X509CRL) certFactory.generateCRL(crlStream);
        return crl.isRevoked(cert);

    }

    /**
     * Usage info
     */
    static void usage() {
        String fileName = new File(PDFSignatureInfo.class.getProtectionDomain().getCodeSource()
                .getLocation().getPath()).getName();
        System.out.println();
        System.out.println("Argumentos invalidos");
        System.out.println();
        System.out.println("Uso: " + fileName + " -infile ArquivoAssinado.(p7s|pdf) " +
                "[-outfile ArquivoExtraido.pdf -outjson ArquivoDados.json]");
        System.out.println();
    }
}
