import base64
import hmac
import hashlib
import json
import secrets
import zlib
import time
import datetime
import random
import string

BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

class BadSignature(Exception):
    """Signature does not match."""
    pass

class SignatureExpired(BadSignature):
    """Signature timestamp is older than required max_age."""
    pass

class JSONSerializer:
    """
    Simple wrapper around json to be used in signing.dumps and
    signing.loads.
    """
    def dumps(self, obj):
        return json.dumps(obj, separators=(',', ':')).encode('latin-1')

    def loads(self, data):
        return json.loads(data.decode('latin-1'))

class BaseConverter:
    decimal_digits = '0123456789'

    def __init__(self, digits, sign='-'):
        self.sign = sign
        self.digits = digits
        if sign in self.digits:
            raise ValueError('Sign character found in converter base digits.')

    def __repr__(self):
        return "<%s: base%s (%s)>" % (self.__class__.__name__, len(self.digits), self.digits)

    def encode(self, i):
        neg, value = self.convert(i, self.decimal_digits, self.digits, '-')
        if neg:
            return self.sign + value
        return value

    def decode(self, s):
        neg, value = self.convert(s, self.digits, self.decimal_digits, self.sign)
        if neg:
            value = '-' + value
        return int(value)

    def convert(self, number, from_digits, to_digits, sign):
        if str(number)[0] == sign:
            number = str(number)[1:]
            neg = 1
        else:
            neg = 0

        # make an integer out of the number
        x = 0
        for digit in str(number):
            x = x * len(from_digits) + from_digits.index(digit)

        # create the result in base 'len(to_digits)'
        if x == 0:
            res = to_digits[0]
        else:
            res = ''
            while x > 0:
                digit = x % len(to_digits)
                res = to_digits[digit] + res
                x = int(x // len(to_digits))
        return neg, res


base62 = BaseConverter(BASE62_ALPHABET)

def force_bytes(s, encoding='utf-8', errors='strict'):
    if isinstance(s, bytes):
        if encoding == 'utf-8':
            return s
        else:
            return s.decode('utf-8', errors).encode(encoding, errors)
    return str(s).encode(encoding, errors)

def salted_hmac(key_salt, value, secret=None, *, algorithm='sha1'):
    key_salt = force_bytes(key_salt)
    secret = force_bytes(secret)
    try:
        hasher = getattr(hashlib, algorithm)
    except AttributeError as e:
        raise ValueError(
            '%r is not an algorithm accepted by the hashlib module.'
            % algorithm
        ) from e
    key = hasher(key_salt + secret).digest()
    return hmac.new(key, msg=force_bytes(value), digestmod=hasher)

def b64_encode(s):
    return base64.urlsafe_b64encode(s).strip(b'=')

def b64_decode(s):
    pad = b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def base64_hmac(salt, value, key, algorithm='sha1'):
    return b64_encode(salted_hmac(salt, value, key, algorithm=algorithm).digest()).decode()

def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return secrets.compare_digest(force_bytes(val1), force_bytes(val2))

def random_string(length=32):
    return "".join(
        random.SystemRandom().choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits
        )
        for _ in range(length)
    )

class Signer:
    def __init__(self, appId, appSignKey, sep=":", algorithm=None):
        self.appId = str(appId)
        self.sep = sep
        self.appSignKey = str(appSignKey)
        self.algorithm = algorithm or "sha1"
    
    def signature(self, value):
        return base64_hmac(self.appId + 'signer', value, self.appSignKey, algorithm=self.algorithm)

    def sign(self, value):
        return '%s%s%s' % (value, self.sep, self.signature(value))

    def unsign(self, signed_value):
        if self.sep not in signed_value:
            raise BadSignature('No "%s" found in value' % self.sep)
        value, sig = signed_value.rsplit(self.sep, 1)
        if constant_time_compare(sig, self.signature(value)):
            return value
        raise BadSignature('Signature "%s" does not match' % sig)

    def sign_object(self, obj, serializer=JSONSerializer, compress=False):
        data = serializer().dumps(obj)
        # Flag for if it's been compressed or not.
        is_compressed = False

        if compress:
            # Avoid zlib dependency unless compress is being used.
            compressed = zlib.compress(data)
            if len(compressed) < (len(data) - 1):
                data = compressed
                is_compressed = True
        base64d = b64_encode(data).decode()
        if is_compressed:
            base64d = '.' + base64d
        return self.sign(base64d)

    def unsign_object(self, signed_obj, serializer=JSONSerializer, **kwargs):
        # Signer.unsign() returns str but base64 and zlib compression operate
        # on bytes.
        base64d = self.unsign(signed_obj, **kwargs).encode()
        decompress = base64d[:1] == b'.'
        if decompress:
            # It's compressed; uncompress it first.
            base64d = base64d[1:]
        data = b64_decode(base64d)
        if decompress:
            data = zlib.decompress(data)
        return serializer().loads(data)

class TimestampSigner(Signer):

    def timestamp(self):
        return base62.encode(int(time.time()))

    def sign(self, value):
        value = '%s%s%s' % (value, self.sep, self.timestamp())
        return super().sign(value)

    def unsign(self, value, max_age=None):
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        result = super().unsign(value)
        value, timestamp = result.rsplit(self.sep, 1)
        timestamp = base62.decode(timestamp)
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = time.time() - timestamp
            if age > max_age:
                raise SignatureExpired(
                    'Signature age %s > %s seconds' % (age, max_age))
        return value


class ApiSigner(TimestampSigner):
    def sign_data(self, data):
        data['appId'] = self.appId
        data['timestamp'] = int(time.time())
        data['nonce'] = random_string()
        data['sign'] = super().sign_object(data)
        return  data

    def unsign_data(self, signed_data, max_age=120):
        sign_string = signed_data.pop('sign', '')
        return super().unsign_object(sign_string, max_age=max_age)
        