from signing import Signer, TimestampSigner, ApiSigner

appId=12345678
appSignKey = "9C28F426-7DBA-488A-8C80-B3AD2C5653C1"

s = Signer(appId, appSignKey)
print(s.sign('aaaa'))
print(s.unsign('aaaa:vcMl7JP9fk8DJSwr8_4dgZIr-rI'))

print(s.sign_object({'a': 1, 'b': 2}))
print(s.unsign_object('eyJhIjoxLCJiIjoyfQ:_Mq1KDMdlbqt4SqCOYDInHB7rVc'))

t = TimestampSigner(appId, appSignKey)
print(t.sign('aaaa'))
# print(t.unsign('aaaa:1oljCu:Ks4I2_uXEUSeprmLZg1fCZglzps', max_age=1000))

a = ApiSigner(appId, appSignKey)
print(a.sign_data({'query': 123}))
a_s = {'query': 123, 'appId': '123456781', 'sign': 'eyJxdWVyeSI6MTIzLCJhcHBJZCI6IjEyMzQ1Njc4In0:1ollDm:_pHdHoKZw6rtGagrdrbtjwhAuiI'}
print(a.unsign_data(a_s))