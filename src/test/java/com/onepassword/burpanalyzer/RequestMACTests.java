package com.onepassword.burpanalyzer;

import com.onepassword.burpanalyzer.model.RequestMAC;
import com.onepassword.burpanalyzer.model.RequestMAC.RequestMethod;
import com.onepassword.burpanalyzer.model.RequestMAC.VersionIndicator;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;
import java.util.List;

@RunWith(Parameterized.class)
public class RequestMACTests {
    public RequestMACTests(String expected, String sessionId, long requestId, RequestMethod requestMethod, URL url, byte[] sessionKey) {
        this.expected = expected;
        this.sessionId = sessionId;
        this.requestId = requestId;
        this.requestMethod = requestMethod;
        this.url = url;
        this.sessionKey = sessionKey;
    }

    private final String expected;
    private final String sessionId;
    private final long requestId;
    private final RequestMethod requestMethod;
    private final URL url;
    private final byte[] sessionKey;

    @Parameterized.Parameters
    public static List<Object[]> data() throws MalformedURLException {
        return List.of(
            new Object[]{"v1|6|oBnE8JLpG2Othzgy",
                    "RDPMIFQWUJBWZFDBKURHNRFVRA", 6L, RequestMethod.GET,
                    new URL("https://my.b5local.com:3000/api/v1/invites"),
                    Base64.getUrlDecoder().decode("ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM")
            },
            new Object[] {"v1|7|E2w1PDPlDRKaVEQs",
                    "RDPMIFQWUJBWZFDBKURHNRFVRA", 7L, RequestMethod.GET,
                    new URL("https://my.b5local.com:3000/api/v2/users?limit=25&states=P&types=G,R"),
                    Base64.getUrlDecoder().decode("ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM")
            },
            new Object[] { "v1|7|JDqt1exoqPCjZiAJ",
                    "QVLABIG34RB3TMH7ZJEW47CCKE", 7L, RequestMethod.GET,
                    new URL("https://my.b5local.com:3000/api/v1/vaults?permission=read&attrs=accessor-previews%2Ccombined-access"),
                    Base64.getUrlDecoder().decode("-K_oZ-mtamTiLJODQn5cVhXQX-nFmPI2kosmWmOWfZg") },
            new Object[]{"v1|3907223784|Htb-Sn_9k4u59wOz",
                    "VADBXWG7FVC6FIOKOJ4DBGE4SY", 3907223784L, RequestMethod.DELETE,
                    new URL("https://awesome.b5dev.com/api/v1/vault/p3nfd4jax622nqjos7licewuyn"),
                    Base64.getUrlDecoder().decode("xvoJlJo7KkJGQ55-mjd7tOBE6YvRYnGBNpPoo3_F2M0")
            },
            new Object[]{"v1|781158249|kkvpSd6stufwwlsZ",
                    "2UG2ZGCDLFAWRHPETAV325EL5U", 781158249L, RequestMethod.GET,
                    new URL("https://awesome.b5dev.com/api/v1/auditevents/0/older?object_types=gva,invite"),
                    Base64.getUrlDecoder().decode("WDs9nvg0DYYmQmucwPZ25FV6uUSaYsJUgse7apbs6rk")
            }
        );
    }

    @Test
    public void createMacForRequest() {
        var mac = new RequestMAC(VersionIndicator.v1, this.requestMethod, this.sessionId,
                                    this.requestId, this.url);

        var headerRes = mac.generateRequestHeader(this.sessionKey);

        Assert.assertTrue("MAC generation works", headerRes.isOk());
        Assert.assertEquals("MAC generation generates expected value", this.expected, headerRes.getResult());
    }
}
