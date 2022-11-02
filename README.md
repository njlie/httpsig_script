# httpsig script

A simple script that will generate httpsig headers for your request.

## Usage

Run `yarn` to install dependencies, then import this module into an interactive node instance. It exports the following functions: `generateTestKeys` and `generateSigHeaders`

* `generateTestKeys()`: Takes no parameters. Use this to generate the private key that will be used to create the signature and the public key that will be passed to a server to verify it.
  * Returns two JWKs like so: `{ privateKey, publicKey }`
* `generateSigHeaders(privateKey: JWK, path: string, method: string, body: Object, authorization: string)`: Used to generate the headers of a signed request using httpsig. Returns a `headers` object containing said headers, as well as the `challenge` that was signed.
  * `{ headers: Object, challenge: string }`