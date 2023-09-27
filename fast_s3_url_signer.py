import datetime
import hashlib
import hmac
import urllib.parse


class FastS3UrlSigner:
    """
    A performant version with plain vanilla implementation of AWS S3 URL signing; no dependencies are required.
    Signs the URLs with AWS SigV4 signing process

    The impl taken from here: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """

    def __init__(self, region, access_key, secret_key):
        self.service = 's3'

        self.region = str(region).lower()
        self.access_key = access_key
        self.secret_key = secret_key

    def get_signed_url(self, bucket_name: str, object_key: str, expiry_in_seconds=9000):
        return self.__get_presigned_url(bucket_name=bucket_name, object_key=object_key, method_name='GET', expiry_in_seconds=expiry_in_seconds)

    def generate_signed_put_url(self, bucket_name: str, object_key: str, expiry_in_seconds=9000):
        return self.__get_presigned_url(bucket_name=bucket_name, object_key=object_key, method_name='PUT', expiry_in_seconds=expiry_in_seconds)

    def __get_host(self, bucket_name, region):
        if region == "us-east-1":
            return f"{bucket_name}.s3.amazonaws.com"
        return f"{bucket_name}.s3.{region}.amazonaws.com"

    def __sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def __get_signature_key(self, key, date_stamp, region_name, service_name):
        k_date = self.__sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = self.__sign(k_date, region_name)
        k_service = self.__sign(k_region, service_name)
        k_signing = self.__sign(k_service, 'aws4_request')
        return k_signing

    def __get_presigned_url(self, bucket_name: str, object_key: str, method_name: str, expiry_in_seconds: int):
        host = self.__get_host(bucket_name=bucket_name, region=self.region)
        _object_key = urllib.parse.quote(object_key)
        expiry_in_seconds = expiry_in_seconds

        t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')  # Format date as YYYYMMDD'T'HHMMSS'Z'
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
        canonical_uri = '/' + _object_key
        canonical_headers = 'host:' + host + '\n'
        signed_headers = 'host'

        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + self.region + '/' + self.service + '/' + 'aws4_request'

        canonical_querystring = ''
        canonical_querystring += 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            self.access_key + '/' + credential_scope
        )
        canonical_querystring += '&X-Amz-Date=' + amz_date
        canonical_querystring += '&X-Amz-Expires=' + str(expiry_in_seconds)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        canonical_request = (
            method_name
            + '\n'
            + canonical_uri
            + '\n'
            + canonical_querystring
            + '\n'
            + canonical_headers
            + '\n'
            + signed_headers
            + '\n'
            + 'UNSIGNED-PAYLOAD'
        )

        string_to_sign = (
            algorithm
            + '\n'
            + amz_date
            + '\n'
            + credential_scope
            + '\n'
            + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        )

        signing_key = self.__get_signature_key(self.secret_key, datestamp, self.region, self.service)

        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        request_url = "https://" + host + canonical_uri + "?" + canonical_querystring
        return request_url
