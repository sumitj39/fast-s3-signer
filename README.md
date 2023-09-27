# fast-s3-signer
Custom S3 URL signer written in Python that is 10-50x faster than boto3 signer. It has zero library dependencies.

## Installation
It's a single file python file, you can copy paste it into your project and modify as needed.

## Usage
```python
# Create an instance of the signer object
s = FastS3UrlSigner(region="ap-south-1", access_key="access-key", secret_key="secret_key")

# Generate a presigned GET URL with expiry of 2 hours
url = s.generate_signed_url(bucket_name="sample-bucket", object_key="sample-key", expiry_in_seconds=7200)

# Generate a presigned PUT URL with default expiry (3600s or 1 hour)
put_url = s.generate_signed_put_url(bucket_name="sample-bucket", object_key="sample-key")
```
