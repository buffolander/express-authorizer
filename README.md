> This Express middleware accepts a Swagger (OAS2) specification file for input and maps all routes found in the document to your server. 

> The built-in validator method verifies required headers and validates request bodies against schemas found in the Swagger file. 

> The emiter method is responsible for returning standardized responses as outlined in Swagger specifications, making it easier to enforce consistency in your API responses.

## Usage

server.js

```javascript
const express = require('express')
const path = require('path')

const { routes, validator } = require('@brdu/express-swagger')({
  swaggerPath: path.resolve(__dirname, './config/swagger-mock.yaml'),
  controllersPath: path.resolve(__dirname, './controllers'),
}) /* Initialize middleware; initialization schema

  type: object
  required:
    - swaggerPath
    - controllersPath
  properties:
    swaggerPath:
      type: string
      description: >-
        Path your API Specification in Swagger (OAS2) YAML
    controllersPath:
      type: string
      description: >-
        Path to your API Controllers
    fileNameCasing:
      type: string
      enum:
        - KEBAB
        - CAMEL
        - SNAKE
      default: KEBAB
      description: >-
        Casing convention used in your directories and files
*/

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

/*
  Create server routes found in your API Specifications
  It's based on the 'routes' array; generated when the middleware is initialized
  The request passes through the validator, before reaching the associated controller
*/
routes.map(({
  fullPath,
  method,
  controller,
  parameters,
  responses,
}) => app[method](
  fullPath,
  (req, res, next) => validator(req, res, next, parameters, responses),
  controller,
))

const port = process.env.PORT || 8080
app.listen(port, () => {
  console.log('app listening on port', port)
})
```

controllers/getResourceById.js

```javascript
module.exports = (req, res) => {
  /*
    The validator middleware injects the emiter method into the res object
    Use to return standardized responses, adherent to your specifications
  */
  return res.emiter({
    res,
    code: 200,
    data: {
      // any data returned from your database or other services
    },
  })
}
```
