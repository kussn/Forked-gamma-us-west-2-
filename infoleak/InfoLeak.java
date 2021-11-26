package com.zme.zmecontentassetprocessor.filter;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.filter.GenericFilterBean;

import com.zme.zmecontentasset.util.RedactUtils;
import com.zme.zmecontentassetprocessor.servlet.AccessibleServletRequest;

import amazon.odin.awsauth.OdinKeyPair;

/**
 * Verify request signatures: the caller didn't change the query-string between
 * getting it from CALS and calling us.
 */
public class SignatureFilter extends GenericFilterBean {
    private Logger logger = Logger.getLogger(getClass());

    protected static final String VALIDSIG_ATTR = "ValidSignature";
    protected static final String HTTP_PROTOCOL = "http://";
    protected static final String HTTPS_PROTOCOL = "https://";
    private static final String HMAC_SHA256 = "HmacSHA256";

    public final static class SignatureMismatchException extends
        RuntimeException {
        public SignatureMismatchException(Exception e) {
            super(e);
        }
        public SignatureMismatchException(String message) {
            super(message);
        }
        public SignatureMismatchException() {
            super();
        }
    }

    protected final Map<Long, OdinKeyPair> keys = new ConcurrentHashMap<>();
    protected final String materialName;

    private Set<String> ignorableParameters = new HashSet<String>() {
        {
            add("sig");
            add("serial");
            add("setupMultipartUpload");
            add("completeMultipartUpload");
            add("abortMultipartUpload");
            add("part");
            add("checksum");
        }
    };

    public SignatureFilter(String materialName) {
        this.materialName = materialName;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        verifySignature((AccessibleServletRequest) request);
        chain.doFilter(request, response);
    }

    protected String getSig(AccessibleServletRequest request) {
        return request.getParameter("sig");
    }

    protected String getSerial(AccessibleServletRequest request) {
        return request.getParameter("serial");
    }

    protected byte[] getSigBytes(String sig) {
        try {
            return Hex.decodeHex(sig.toCharArray());
        }
        catch (DecoderException e) {
            throw new IllegalArgumentException("Invalid Signature", e);
        }
    }

    void verifySignature(AccessibleServletRequest request) throws URIException {
        try {
            String sig = getSig(request);

            Validate.notNull(sig, "'sig' is required!");
            String serial = getSerial(request);
            Validate.notNull(serial, "'serial' is required!");

            String parsedUrl = getUrlToSign(request);
            logger.info("{"
                + "\n requestUrl:" + RedactUtils.redact(request.getRequestURL().toString() +
                (request.getQueryString() == null ? "" : "?" + request.getQueryString()), sig)
                + "\n parsedUrl:" + parsedUrl
                + "\n MaterialSet:" + materialName
                + "\n method:" + request.getMethod() + "}");

            byte[] sigBytes = getSigBytes(sig);

            byte[] data = org.apache.commons.codec.binary.StringUtils.getBytesUtf8(parsedUrl);

            //Setting to false to override any user-supplied attribute
            request.setAttribute(VALIDSIG_ATTR, false);
            if(!RequestMethod.OPTIONS.name().equals(request.getMethod())) {
                verifySignature(Long.parseLong(serial), data, sigBytes);
            }
            request.setAttribute(VALIDSIG_ATTR, true);
        }
        catch (IllegalArgumentException e) {
            // Any IllegalArgument to the signature-handler must be an attempt to
            // change the signature. 403, not 400.
            throw new SignatureMismatchException(e);
        }
    }

    protected void verifySignature(long serial, byte[] data, byte[] actualSig) {
        // 0 means use the latest serial to OdinKeyPair and that is not valid
        // behavior for CAPS.
        if (serial == 0) {
            throw new IllegalArgumentException("Invalid Serial");
        }
        OdinKeyPair keyPair = keys.computeIfAbsent(serial, ser -> {
            try {
                return new OdinKeyPair(materialName, ser);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid Serial");
            }
        });

        byte[] expectedSig = signBytes(keyPair.getVersionedKeyPair().getSecret().getPrivate().getEncoded(), data);
        // Use MessageDigest.isEqual instead of (for example) Arrays.equals,
        // to prevent timing attacks on our signatures. Assumes we're using
        // a recent version of java, per the article below.
        // (`java -version` > 1.6.0_17; see the note at the very end of the article.)
        //
        // "What's a timing attack?":
        // http://codahale.com/a-lesson-in-timing-attacks/
        //
        // Why not use Odin's sign/verify instead, which (I assume) do this for
        // us? Because a 256-character hex-encoded signature is way too long
        // for a URL; and we're okay with symmetric keys, ie. we trust both CAPS
        // and CALS to read the "private key". (If we didn't trust CAPS xor CALS,
        // we'd need to use asymmetric keys and the HMAC approach used here
        // wouldn't work.)
        boolean matches = MessageDigest.isEqual(actualSig, expectedSig);

        if (!matches) {
            String actualSignature = new String(Hex.encodeHex(actualSig));
            logger.info("Invalid signature supplied: '" + actualSignature + "'");
            throw new SignatureMismatchException("'" + actualSignature + "' is invalid.");
        }
    }

    public static byte[] signBytes(byte[] key, byte[] data) {
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA256);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    String getUrlToSign(AccessibleServletRequest request) {
        String url = forceHttpsProtocol(request.getRequestURL().toString());
        if(!StringUtils.isEmpty(request.getQueryString())) {
            url += "?" + removeParameters(request.getQueryString(), ignorableParameters);
        }

        return url;
    }

    /*
     * JlbRelay translates requests to HTTP before sending to CAPS.
     * Since CALS signs with the protocol set to HTTPS, we need to pretend this request was HTTPS when signing.
     */
    String forceHttpsProtocol(String rawUrl) {
        if (HTTP_PROTOCOL.equals(rawUrl.substring(0, HTTP_PROTOCOL.length()))) {
            return HTTPS_PROTOCOL + rawUrl.substring(HTTP_PROTOCOL.length());
        }
        return rawUrl;
    }

    String removeParameters(String url, Set<String> removableParameters) {
        StringBuilder builder = new StringBuilder();
        String[] parameters = url.split("&");
        for(String parameter : parameters) {
            String key = parameter.split("=")[0];
            if(removableParameters.contains(key)) {
                continue;
            }
            builder.append(parameter);
            builder.append("&");
        }
        builder.deleteCharAt(builder.length()-1);
        return builder.toString();
    }

    public static boolean isSignatureValid(AccessibleServletRequest request) {
        return BooleanUtils.isTrue((Boolean)request.getAttribute(VALIDSIG_ATTR));
    }
}