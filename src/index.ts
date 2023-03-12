import axios from 'axios';
import OAuth from 'oauth-1.0a';
import crypto from 'crypto';
import FormData from 'form-data';

interface Credentials {
  domain: string;
  consumer_key: string;
  consumer_secret: string;
  access_token: string;
  access_secret: string;
}

interface Props {
  endpoint: string;
  credentials: Credentials;
  data?: Record<string, string>;
  formData?: FormData;
}

export default async function call({ endpoint, credentials, data, formData }: Props) {
  const { domain, consumer_key, consumer_secret, access_token = '', access_secret = '' } = credentials;
  const token = { key: access_token, secret: access_secret };
  const oauth = new OAuth({
    consumer: { key: consumer_key, secret: consumer_secret },
    signature_method: 'HMAC-SHA1',
    hash_function(baseString: string, key: string) {
      return crypto.createHmac('sha1', key).update(baseString).digest('base64');
    }
  });

  const requestData = { url: `https://${domain}${endpoint}`, method: 'POST', data };
  const headerOauth = oauth.toHeader(oauth.authorize(requestData, token));
  const headerContentType = !!formData
    ? formData.getHeaders()
    : { 'Content-Type': 'application/x-www-form-urlencoded' };

  return axios.post(requestData.url, !!formData ? formData : new URLSearchParams(requestData.data).toString(), {
    headers: { ...headerOauth, ...headerContentType }
  });
}
