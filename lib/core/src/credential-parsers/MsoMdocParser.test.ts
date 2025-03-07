

import { assert, describe, it } from "vitest";
import { Context, HttpClient } from "../interfaces";
import axios, { AxiosHeaders } from "axios";
import { MsoMdocParser } from './MsoMdocParser';

const issuerSignedB64U = `omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQS62BhZBLWnZnN0YXR1c6Frc3RhdHVzX2xpc3SiY2lkeBhsY3VyaXhWaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL3N0YXR1cy84ODc5M2MwMy0xNmFkLTQ0NjgtYmVmNy1jMDgzZDM4YWUyMTlnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xOFQxNDoxMjowNFppdmFsaWRGcm9twHQyMDI1LTAyLTE4VDE0OjEyOjA0Wmp2YWxpZFVudGlswHQyMDI1LTAzLTA0VDE0OjEyOjA0Wmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xtgBYIKuGxnFMGhNio5-VUJKePlkmw33mloMA9fgqUR0ynOoJAVggWxNyUrVxTPW2riSGxx_U_irluD-vcJIOGGrafGo6JpwCWCDKOCdlxlbeX7mztFkzrM7MsZHs3gEyrmC79X3N2VpxkgNYICmI6iaQPBePM7fzBXqPyX5Gr-wNnWNCNb7wDUz4VDIRBFggfCuu8bFboi9BiRPsM447Ncg9A7K7A28iTEjVy9fmjBIFWCC6z1AlQM8ttJfuIQtPYlurlamh3MvAbSaQoUzAn-9L9gZYIKD1mVbZ5zb-_sp_E6vZCQ_U2QAQVNtbWAznR4xUm6LoB1ggWAn0OSPMM-m8NbgBZ-D6qLV0BEVeSnR4DIsUPUOZDbsIWCDyTDBH9XjK_JIq_W7d19UpmMq1pd1CjrmhfIHsctg3gwlYIK7ejRc3g-pfNGM0WHv4Oh1jfshl03Jvm3cxKHFnIIXmClggjPVDgZmiJEpnM6Zo_mzUQAbW5M6QZuRH43L6BqVeT7wLWCCSVNDu2CjnRkbC7_6m6-G6h8dTDWvlmGz0WD-MUCGERwxYIDpAXdFHgnACMgICXQpJi9nzBDRjsJ8bY1htM9GtgZlKDVggvhyWJk8WGQgokFghnd9DyZKyo8b6VrfAX8WTB0vH1QkOWCBLJFY_nbKL1x-5fbJCqS1IgEn_uMm9NJm2vqorCWwwPg9YIJIg7rTS_E3HAYjcjdV6WSpgZuXa8IKo7f5aC9ibPXQzEFggc_BlS8FdmjVtSqXrA2Xh58naoO0XdTbwclGo9itNTIERWCDzIo5muAIWaawEG69bUPG4mI4pEB5dUhadaUeMUEuwIhJYIEALsAqnwl3T1nC7YtOeDj-7OEHlmcwhCZjY2Qgsr2vCE1ggwG6In0GuGqO1isPXfh2EA7-mi18JAhfumCyQUA5FpYYUWCAL6kBisfFYUIU06t2d0UeqElM-c49VrVqfgYYSIx2JpRVYICYx93c95xCPFdhE03ZlReMnLGSjT_SJgEBMeErv0VlXbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgganiJYJ0goJBbFzWZ52BDtTvTP1Fqb6k80C4UBl6JrFwiWCCWf2o4RIOTRI_UGubc0rCyIDo-o_LYRzYRnWzos3gcSm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAcBP9-i1suGc_TnH7z4Mp8jFAz2Q__4w7Ju7dDG93XWfCE15E15WYaXUnkYY80tStLInk7nEi6IqEPHJPUyWiyGpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMZbYGFhRpGZyYW5kb21Q6lwO6tOJcjKhPDMrRPrRFGhkaWdlc3RJRABsZWxlbWVudFZhbHVlGDxxZWxlbWVudElkZW50aWZpZXJsYWdlX2luX3llYXJz2BhYT6RmcmFuZG9tUBwuvU0MGGbT2h94xazpeqloZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhdpGZyYW5kb21Qo6kOsHqedb_9xHVlfCXHf2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZTUxMTQ3cWVsZW1lbnRJZGVudGlmaWVydHJlc2lkZW50X3Bvc3RhbF9jb2Rl2BhYVaRmcmFuZG9tUP6aK3BnaJ4ssYCnhgPSaZpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWZCRVJMSU5xZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2XYGFhPpGZyYW5kb21QGR_ZD_ylLFjp_gFyoXxR0WhkaWdlc3RJRARsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFWkZnJhbmRvbVByTlMf_mCOUvaECM5veox_aGRpZ2VzdElEBWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYY6RmcmFuZG9tUED3uH1EYolIFfAdQr8v6pVoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZcB0MTk2NC0wOC0xMlQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWE-kZnJhbmRvbVBucDIRMDGt1bMXZVQopw3OaGRpZ2VzdElEB2xlbGVtZW50VmFsdWX0cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzY12BhYVqRmcmFuZG9tUEQqTillqXQcpIwC8F2YOMloZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMoKXZZ4ZDwVRRL4IQ7oDEFoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTbYGFhXpGZyYW5kb21QdJ-5Oz_55VjO0LOBbnoLs2hkaWdlc3RJRApsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYa6RmcmFuZG9tUMexUIlyfvCgcIUu67OBH6doZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDItMThUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYVKRmcmFuZG9tUJ_7jstnoovdbm84Cmh2etFoZGlnZXN0SUQMbGVsZW1lbnRWYWx1ZRkHrHFlbGVtZW50SWRlbnRpZmllcm5hZ2VfYmlydGhfeWVhctgYWFmkZnJhbmRvbVAnc4IFpUS4gxjqo-1DsQNvaGRpZ2VzdElEDWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWE-kZnJhbmRvbVD0dq9e6pNoaa0e_tVlZ-hZaGRpZ2VzdElEDmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYU6RmcmFuZG9tUIurbtyPoiia4qsc62iQHIBoZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZWVFUklLQXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tUKgfL0gkbSOApy2APkdkNatoZGlnZXN0SUQQbGVsZW1lbnRWYWx1ZXBIRUlERVNUUkHhup5FIDE3cWVsZW1lbnRJZGVudGlmaWVyb3Jlc2lkZW50X3N0cmVldNgYWFGkZnJhbmRvbVA3gWJEwZz8jgsLsfRJvjMQaGRpZ2VzdElEEWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHnYGFhPpGZyYW5kb21QHSMBCaBxBPPy92dCcmoZvWhkaWdlc3RJRBJsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMdgYWFakZnJhbmRvbVB4Df01yH0SBmag1gS4xKL9aGRpZ2VzdElEE2xlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWFukZnJhbmRvbVDxOTqapogRuHVS1cLoK7z6aGRpZ2VzdElEFGxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYaaRmcmFuZG9tUOFMkL6pWaVejQQEv7_aS-loZGlnZXN0SUQVbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDMtMDRUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZQ`;
const deviceResponseB64U = `uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xlNgYWFmkZnJhbmRvbVBIKMdczA7zHxWIMiZNiEw6aGRpZ2VzdElEBGxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWFOkZnJhbmRvbVBSAcocu4luUU9h1OG6mb3KaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVlRVJJS0FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWFukZnJhbmRvbVCg8N7UF3UtjNT5rrcv4I0naGRpZ2VzdElECmxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYY6RmcmFuZG9tUPh214HbpajZ129WkN0HEGxoZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZcB0MTk2NC0wOC0xMlQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWE-kZnJhbmRvbVBCI4bNHyJLeZiqCCWOeSXSaGRpZ2VzdElEFGxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzEy2BhYT6RmcmFuZG9tUHUL5DoK1Q6XGSIK2KpqX5VoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTTYGFhPpGZyYW5kb21QOsF40fU9yz-5ElPgowWmo2hkaWdlc3RJRBFsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWE-kZnJhbmRvbVDN7ONl9EGf6JhCDbHBMxjPaGRpZ2VzdElEAWxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYT6RmcmFuZG9tUHP_XGaz0ceKD_vmjJikW-VoZGlnZXN0SUQSbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMjHYGFhPpGZyYW5kb21Q19-nAhWrgR8HBaghg8XwKGhkaWdlc3RJRAlsZWxlbWVudFZhbHVl9HFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl82NdgYWFGkZnJhbmRvbVARyyxLhICjQCleUZjdlJNnaGRpZ2VzdElEAmxlbGVtZW50VmFsdWUYPHFlbGVtZW50SWRlbnRpZmllcmxhZ2VfaW5feWVhcnPYGFhUpGZyYW5kb21Qz5JnWxDm2R3cfbpiXNHuhGhkaWdlc3RJRAtsZWxlbWVudFZhbHVlGQescWVsZW1lbnRJZGVudGlmaWVybmFnZV9iaXJ0aF95ZWFy2BhYVaRmcmFuZG9tUAyz52Pd2a2dIuVbL77HwU9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZWZCRVJMSU5xZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2XYGFhRpGZyYW5kb21QHrqyCHgoG-r6n5gipksku2hkaWdlc3RJRBBsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVya25hdGlvbmFsaXR52BhYVqRmcmFuZG9tUDs7795UIU3mGifs9fSMyk9oZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYXaRmcmFuZG9tUKQVC8WZ0niGucqWS7wHZpdoZGlnZXN0SUQMbGVsZW1lbnRWYWx1ZWU1MTE0N3FlbGVtZW50SWRlbnRpZmllcnRyZXNpZGVudF9wb3N0YWxfY29kZdgYWFakZnJhbmRvbVB-oVAOiGgWAPkD98PcvMfOaGRpZ2VzdElEDmxlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWGOkZnJhbmRvbVBf5UWUDodw1fG9za4erAEEaGRpZ2VzdElEFWxlbGVtZW50VmFsdWVwSEVJREVTVFJB4bqeRSAxN3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXTYGFhVpGZyYW5kb21Q-THkF_aDlPbGInevZoEuHmhkaWdlc3RJRA1sZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWFekZnJhbmRvbVCQ0ozPJ1JCVER7YRG_k4WRaGRpZ2VzdElEBWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHlqaXNzdWVyQXV0aIRDoQEmoRghglkCeDCCAnQwggIboAMCAQICAQIwCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAkRFMQ8wDQYDVQQHDAZCZXJsaW4xHTAbBgNVBAoMFEJ1bmRlc2RydWNrZXJlaSBHbWJIMREwDwYDVQQLDAhUIENTIElERTE2MDQGA1UEAwwtU1BSSU5EIEZ1bmtlIEVVREkgV2FsbGV0IFByb3RvdHlwZSBJc3N1aW5nIENBMB4XDTI0MDUzMTA4MTMxN1oXDTI1MDcwNTA4MTMxN1owbDELMAkGA1UEBhMCREUxHTAbBgNVBAoMFEJ1bmRlc2RydWNrZXJlaSBHbWJIMQowCAYDVQQLDAFJMTIwMAYDVQQDDClTUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDhQauGDCoOMOX04n7MrcAbiX_-xO1YUT14jZudkt6tREyIAXV8gyt5FcRsYHhz4ryz97rjL0uogxHO6jMZr3bijgZAwgY0wHQYDVR0OBBYEFIj4QpCxKw1zy1tvydFlXoIcsPpiMAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgeAMC0GA1UdEQQmMCSCImRlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUwHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wCgYIKoZIzj0EAwIDRwAwRAIgG3-U85HEM4X1qCKMotVTe3fCPQbBSptTFpbkaYdm8hkCICmJHazX9sVz41Um41v1P-UubwBAuV8XDmp7rDga6AW1WQJ9MIICeTCCAiCgAwIBAgIUB5E9QVZtmUYcDtCjKB_H3VQv72gwCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAkRFMQ8wDQYDVQQHDAZCZXJsaW4xHTAbBgNVBAoMFEJ1bmRlc2RydWNrZXJlaSBHbWJIMREwDwYDVQQLDAhUIENTIElERTE2MDQGA1UEAwwtU1BSSU5EIEZ1bmtlIEVVREkgV2FsbGV0IFByb3RvdHlwZSBJc3N1aW5nIENBMB4XDTI0MDUzMTA2NDgwOVoXDTM0MDUyOTA2NDgwOVowgYgxCzAJBgNVBAYTAkRFMQ8wDQYDVQQHDAZCZXJsaW4xHTAbBgNVBAoMFEJ1bmRlc2RydWNrZXJlaSBHbWJIMREwDwYDVQQLDAhUIENTIElERTE2MDQGA1UEAwwtU1BSSU5EIEZ1bmtlIEVVREkgV2FsbGV0IFByb3RvdHlwZSBJc3N1aW5nIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYGzdwFDnc7-Kn5ibAvCOM8ke77VQxqfMcwZL8IaIA-WCROcCfmY_giH92qMru5p_kyOivE0RC_IbdMONvDoUyaNmMGQwHQYDVR0OBBYEFNRWGMCJOOgOWIQYyXZiv6u7xZC-MB8GA1UdIwQYMBaAFNRWGMCJOOgOWIQYyXZiv6u7xZC-MBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIGEm7wkZKHt_atb4MdFnXW6yrnwMUT2u136gdtl10Y6hAiBuTFqvVYth1rbxzCP0xWZHmQK9kVyxn8GPfX27EIzzs1kEudgYWQS0p2ZzdGF0dXOha3N0YXR1c19saXN0omNpZHgAY3VyaXhWaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL3N0YXR1cy84ODc5M2MwMy0xNmFkLTQ0NjgtYmVmNy1jMDgzZDM4YWUyMTlnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xOFQxNDoxMjowNFppdmFsaWRGcm9twHQyMDI1LTAyLTE4VDE0OjEyOjA0Wmp2YWxpZFVudGlswHQyMDI1LTAzLTA0VDE0OjEyOjA0Wmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xtgBYIEirhRmTGLu7J6NTeywbqo9PTcrHsJ8zPZFIRtAT03UGAVggVP9xFV5GEUYAvMAYTu12XMiETKFyfSY_E1ytQ3wWEXwCWCDBdY3nOghQbKW8IorJBwI7XggfSHMzG_EhbyKkv7I5LANYIPMwBStwx36BqJCsA8GLGmDqnHWctgszyIoRsoaAVWhBBFggRHfmXFEsEHtjn2zJBL2IWKw4ZNOpT8r6kPJjnwZSNS4FWCCSerbybLZiNc9iptNvLp1l3m4GFs1YPcrW6Ru9dhy3NgZYIASk7NwYS5ETt8huiKDQZmQsy_0mZNWnRzpBiuMECgzqB1ggJUBadYwH934ZgXzunsol1Fdaip6maDu3ioiRvZWZs5sIWCDyB1u3PsND6w5Fea16X19w01jow9gIBnj5-Zd1P5iy4QlYIM7KAT7aFfJdjiuasohID2iDnwTJv0lg0CjTdNA-XVsnClggW9xddmd5U39UPems65FkBzGzazlYkAPEbTiepxMa2ZALWCAwBnAfgMI0EZzssorAvT5WqKjAoaExVc-oNQQVMIn6yQxYIA7TtHyGykR4SvhDWhJwkPonZG-dxGEe0n2DwmSKt8eNDVggnfiw1cwSIZs77zRvtCwBBLXhbq_-D3mMLET3qBXhMp4OWCBliBbg1MmVDKt3FmaiUTz8-smu5I9Ca3MEY4VtG9AzBA9YIKQGIYCRdKodGbQKKBMTZSTBCl17JOX5HFKRw4YMDaswEFggZ_fgaCdQpN8KGWla7o9pCbBgEh0uE-uggwTb-1XvdZkRWCCJ45ATjvvzDIxX-GuHmzR1fMjziy8mLFe7gghCiwBTsBJYIDmK_FQLWIXDoyFjRrySy2ICsUNlWOZhwgSBoFf5w6mvE1ggosNW9izG0Erb2Wly9ZuEYd0YmVgEf83_8MzMvk31wS0UWCD_R1--R7wILyc3SiOKmRpJ0Dvr5WJLGn2jEexXsFlbPBVYIJqJxtHSoawDNCSVQZppaM2DXLTswuCaeXklOQMfoTLgbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggt06a6xedGC3bshSAiuGceNUnReLTFjzvFUQo-Lqc8LsiWCAX0ZfKPf0xPgaoLThiwwy5uq2F0PotADZmO1WVJRbUS29kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAr01sYZ08XiZQ_ZMIjO4_PZSnVQBChwtXAn3LJXupHXU_8Lk9ZU0zm6IHsGS2viFXBdEomPHj6RF3wmieN7iHFmxkZXZpY2VTaWduZWS5AAJqbmFtZVNwYWNlc9gYQ7kAAGpkZXZpY2VBdXRouQABb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFNKLb4rfqOsmrYXTmGZ31PW8J0APasTdt9W_ejWSNVag0NLgLURJdz0whCa6cAboZNa52XR09U0HjPWL7G1BYBmc3RhdHVzAA`;

const httpClient: HttpClient = {
	async get(url, headers) {
		return axios.get(url, { headers: headers as any }).then((res) => (res?.data ? { status: res.status, data: res.data, headers: res.headers } : {})).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
	async post(url, data, headers) {
		return axios.post(url, data, { headers: headers as any }).then((res) => (res?.data ? { status: res.status, data: res.data, headers: res.headers } : {})).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
}

const context: Context = {
	clockTolerance: 0,
	lang: 'en-US',
	subtle: crypto.subtle,
	trustedCertificates: [],
};

describe("The MsoMdocParser", () => {


	it("should parse a Base64-URL-encoded IssuerSigned object in mso_mdoc format", async () => {
		const parser = MsoMdocParser({ httpClient, context });

		const parsedIssuerSigned = await parser.parse({ rawCredential: issuerSignedB64U });

		assert(parsedIssuerSigned.success);
		assert(parsedIssuerSigned.value.signedClaims["family_name"] === "MUSTERMANN");
		assert(parsedIssuerSigned.value.signedClaims["given_name"] === "ERIKA");
		assert((parsedIssuerSigned.value.signedClaims["birth_date"] as Date).toISOString() === new Date("1964-08-12T00:00:00.000Z").toISOString());
		assert(parsedIssuerSigned.value.validityInfo.signed?.toISOString() === new Date("2025-02-18T14:12:04.000Z").toISOString());
		assert(parsedIssuerSigned.value.validityInfo.validUntil?.toISOString() === new Date("2025-03-04T14:12:04.000Z").toISOString());

	});

	it("should successfully parse a Base64-URL-encoded DeviceResponse in mso_mdoc format", async () => {
		const parser = MsoMdocParser({ httpClient, context });

		const parsedDeviceResponse = await parser.parse({ rawCredential: deviceResponseB64U });
		assert(parsedDeviceResponse.success);

		assert(parsedDeviceResponse.value.signedClaims["family_name"] === "MUSTERMANN");
		assert(parsedDeviceResponse.value.signedClaims["given_name"] === "ERIKA");
		assert((parsedDeviceResponse.value.signedClaims["birth_date"] as Date).toISOString() === new Date("1964-08-12T00:00:00.000Z").toISOString());

	})

})
