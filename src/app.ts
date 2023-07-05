import express, { Express, Request, Response } from 'express';
import config from '../config';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import cors from 'cors';
import { LanguageMiddleware } from './middlewares/language.middleware';
import { UserSessionMiddleware } from './middlewares/session.middleware';
import { authorizationRouter } from './authorization/router';
import AppDataSource from './AppDataSource';
import { openid4vciRouter } from './openid4vci/router';
import locale from './locale';
import { issuersConfigurations, uoaIssuer } from './configuration/IssuersConfiguration';
import createHttpError, { HttpError} from 'http-errors';
import { JWK } from 'jose';

AppDataSource // used for the initizlization of the DB


const app: Express = express();

app.use(cors({ credentials: true, origin: true }));
// __dirname is "/path/to/dist/src"
app.use(express.static(path.join(__dirname, '../../public')));

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true })); // support url encoded bodies
app.use(bodyParser.json()); // support json encoded bodies

app.set('view engine', 'pug');

// __dirname is "/path/to/dist/src"
// public is located at "/path/to/dist/src"
app.set('views', path.join(__dirname, '../../views'));
app.use(LanguageMiddleware);
app.use(UserSessionMiddleware);

app.get('/', async (req: Request, res: Response) => {
	res.render('index', {
		title: "Index",
		credentialIssuerIdentifier: uoaIssuer.credentialIssuerIdentifier,
		lang: req.lang,
		locale: locale[req.lang]
	})
});

app.use('/authorization', authorizationRouter);
app.use('/openid4vci', openid4vciRouter);


const jwks: JWK[] = []
for (const [_, v] of issuersConfigurations) {
	v.exposeConfiguration(app);
	jwks.push()

	const publicKeyJwk = v.legalPersonWallet.keys.ES256?.publicKeyJwk;
	jwks.push({ kid: v.legalPersonWallet.keys.ES256?.id, ...publicKeyJwk });
}
app.get('/jwks', async (_req: Request, res: Response) => {
	res.send(jwks);
})




app.get('/.well-known/openid-configuration', async (_req: Request, res: Response) => {
	const authzServerMetadataConfiguration = {
		"issuer": `${config.url}`,
		"authorization_endpoint": `${config.url}/openid4vci/authorize`,
		"token_endpoint": `${config.url}/openid4vci/token`,
		"jwks_uri": `${config.url}/jwks`,
		"scopes_supported": ["openid"],
		"response_types_supported": ["vp_token", "id_token"],
		"response_modes_supported": ["query"],
		"grant_types_supported": ["authorization_code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["ES256"],
		"request_object_signing_alg_values_supported": ["ES256"],
		"request_parameter_supported": true,
		"request_uri_parameter_supported": true,
		"token_endpoint_auth_methods_supported": ["private_key_jwt"],
		"vp_formats_supported": {
			"jwt_vp": {
				"alg_values_supported": ["ES256"]
			},
			"jwt_vc": {
				"alg_values_supported": ["ES256"]
			}
		},
		"subject_syntax_types_supported": ["did:key"],
		"subject_trust_frameworks_supported": ["ebsi"],
		"id_token_types_supported": [
			"subject_signed_id_token"
		]
	 }
	res.send(authzServerMetadataConfiguration); 
})


// catch 404 and forward to error handler
app.use((_req, _res, next) => {
  next(createHttpError(404));
});

// error handler
app.use((err: HttpError, req: Request, res: Response) => {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error', {
		lang: req.lang,
		locale: locale[req.lang]
	});
});

app.listen(config.port, () => {
	console.log(`eDiplomas app listening at ${config.url}`)
});