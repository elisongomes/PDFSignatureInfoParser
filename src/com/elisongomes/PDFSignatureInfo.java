package com.elisongomes;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class PDFSignatureInfo {

    public Map<String, Object> entries = new HashMap<>();

    public PDFSignatureInfo() {
        this.reason = "";
        this.name = "";
        this.fullName = "";
        this.alternativeName = "";
        this.subFilter = "";
        this.filter = "";
        this.contactInfo = "";
        this.fullContactInfo = "";
        this.location = "";
        this.isSelfSigned = false;
        this.signatureVerified = "";
    }

    public String reason;
    public String name;
    public String fullName;
    public String alternativeName;
    public String subFilter;
    public String filter;
    public String contactInfo;
    public String fullContactInfo;
    public String location;

    public Date signDate;

    public boolean coversWholeDocument;
    public boolean isSelfSigned;

    public String signatureVerified;

    public CertificateInfo certificateInfo;

}