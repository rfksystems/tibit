package com.rfksystems.tibit;

import org.junit.Test;

import java.security.MessageDigest;

import static com.google.common.truth.Truth.*;

public class TibitTest {
    private final long time = 1523459931111L;

    private final byte[][] secrets = {
            "Yh6wUdTbJhZ5JG3yBSPAAakC".getBytes(),
            "KFb68jsQWqmXZeV6yjkrCtk6".getBytes(),
            "mtfnbphnpGgPTJAqpNvSftTK".getBytes(),
            "CMf95zpAwYJST2UKxWVUjxWL".getBytes(),
            "LshjZ6xZkVwD9kgzF2qG8sE2".getBytes(),
            "M8rFf87y22FMhxcBHRh6wwsQ".getBytes(),
            "KWaakVm7L6rxYKA57jZJ9U9E".getBytes(),
            "jnC5Jq3W7WseShqCqaBrkmCU".getBytes(),
            "YPVcYKV3WXzqdzNGkeRtQDYD".getBytes(),
            "P8szNzmdwACbArNDJeSxfKxr".getBytes(),
    };

    private final String[] tibits = {
            "!SHA-256:1523459931111:d90867d98da7ebd2f2f3c4766bae46f46c48457a17e7f842ad4f888699aa0bd7",
            "!SHA-256:1523459931111:d4380882b3c70e891d3ff4b235b76d4ccf12405761c49fbc8f908f208f153b2a",
            "!SHA-256:1523459931111:8f33c7823b9b02d15946a2171f3a91b28d54428aa5e2ea115812969486fc2eae",
            "!SHA-256:1523459931111:500c652c71db5d9134c91df64da69e2b92e50f94e21c7a0f68695c2c1a2060e5",
            "!SHA-256:1523459931111:f405b58fcad94b4a05211287919ba3943eb1ec7ad6a6289b72542aea9d8ecb50",
            "!SHA-256:1523459931111:445a6489e59907d90a5c143ad4a72ba930b90e7399a77b04ce7486f90aa68478",
            "!SHA-256:1523459931111:7c77bdcfeec1cf6c3c10408d68f74ddc5bd310cf81abd5bac7c4d4d99bed2a76",
            "!SHA-256:1523459931111:2230ed4b51265f92e4e16e3e0d4214897498d7a4e6b6008f6170b4a1e1611124",
            "!SHA-256:1523459931111:661dce2f143d2955caa41452ad0e986498566e026f3490b47f85bf87d23b0c40",
            "!SHA-256:1523459931111:a456093d3e1cfd291605db28cc00032fd476849fdb1e8b80926fe1d6c376758b",
    };

    @Test
    public void test() throws Throwable {
        for (int i = 0; i < secrets.length; i++) {
            final byte[] secret = secrets[i];

            final String definedTibit = tibits[i];
            final String generatedTibit = Tibit.create(time, secret, MessageDigest.getInstance("SHA-256"));

            assertThat(definedTibit).isEqualTo(generatedTibit);

            final boolean resultA = Tibit.verify(generatedTibit, secret, time, 0);
            assertThat(resultA).isTrue();

            final boolean resultB = Tibit.verify(generatedTibit, secret, time + 10, 10);
            assertThat(resultB).isTrue();

            final boolean resultC = Tibit.verify(generatedTibit, secret, time - 10, 10);
            assertThat(resultC).isTrue();

            final boolean resultD = Tibit.verify(generatedTibit, secret, time + 11, 10);
            assertThat(resultD).isFalse();

            final boolean resultE = Tibit.verify(generatedTibit, secret, time - 11, 10);
            assertThat(resultE).isFalse();

            final boolean resultF = Tibit.verify(generatedTibit.toUpperCase(), secret, time, 0);
            assertThat(resultF).isTrue();
        }
    }
}
