import express, { Express, Request, Response } from 'express';
import config from '../config';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import cors from 'cors';
import { LanguageMiddleware } from './middlewares/language.middleware';
import { authorizationRouter } from './authorization/router';
import { initDataSource } from './AppDataSource';
import createHttpError, { HttpError} from 'http-errors';
import { appContainer } from './services/inversify.config';
import { FilesystemKeystoreService } from './services/FilesystemKeystoreService';
import { authorizationServerMetadataConfiguration } from './authorizationServiceConfiguration';
import { CredentialReceivingService } from './services/CredentialReceivingService';
import { CredentialIssuersConfigurationService } from './configuration/CredentialIssuersConfigurationService';
import { ExpressAppService } from './services/ExpressAppService';
import { authorizationServerStateMiddleware } from './middlewares/authorizationServerState.middleware';
import { verifierRouter } from './verifier/router';
import locale from './configuration/locale';
import qs from 'qs';
import { applicationMode, ApplicationModeType } from './configuration/applicationMode';

initDataSource();

const credentialReceivingService = appContainer.resolve(CredentialReceivingService);


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


const walletKeystore = appContainer.resolve(FilesystemKeystoreService);

appContainer.resolve(ExpressAppService).configure(app);




app.use(LanguageMiddleware);




app.use('/verifier-panel', verifierRouter);


app.use(authorizationServerStateMiddleware);


app.use('/authorization', authorizationRouter);


// expose all public keys
app.get('/jwks', async (_req: Request, res: Response) => {
	const { keys } = await walletKeystore.getAllPublicKeys();
	res.send({ keys });
})

app.get('/init', async (_req, res) => {
	credentialReceivingService.sendAuthorizationRequest();
	res.send({})
})





app.get('/', async (req: Request, res: Response) => {
	const firstCredentialIssuer = appContainer.resolve(CredentialIssuersConfigurationService)
	.registeredCredentialIssuerRepository()
	.getAllCredentialIssuers()[0];

	if (firstCredentialIssuer
		&& ( applicationMode == ApplicationModeType.ISSUER || applicationMode == ApplicationModeType.ISSUER_AND_VERIFIER)) {
		const firstCredentialIssuerIdentifier = firstCredentialIssuer.credentialIssuerIdentifier;
		return res.render('index', {
			title: "Index",
			credentialIssuerIdentifier: firstCredentialIssuerIdentifier,
			lang: req.lang,
			locale: locale[req.lang]
		})
	}
	else if (applicationMode == ApplicationModeType.VERIFIER) {
		return res.render('verifier/index', {
			title: "Index",
			lang: req.lang,
			locale: locale[req.lang]
		})
	}
	else {
		return res.send({ error: "Error occured" })
	}

});




app.get('/.well-known/openid-configuration', async (_req: Request, res: Response) => {
	res.send(authorizationServerMetadataConfiguration); 
})



app.get('/init/view/:client_type', async (req: Request, res: Response) => {
	const credentialIssuerIdentifier = req.query["issuer"] as string;
	if (!credentialIssuerIdentifier) {
		console.error("Credential issuer identifier not found in params")
		return res.redirect('/');
	}

	const selectedCredentialIssuer = appContainer.resolve(CredentialIssuersConfigurationService)
		.registeredCredentialIssuerRepository()
		.getCredentialIssuer(credentialIssuerIdentifier);
	if (!selectedCredentialIssuer) {
		console.error("Credential issuer not map")
		return res.redirect('/')
	}
	const client_type = req.params.client_type;
	if (!client_type) {
		return res.redirect('/');
	}

	const credentialOfferObject = {
		credential_issuer: selectedCredentialIssuer.credentialIssuerIdentifier,
		credentials: [
			...selectedCredentialIssuer.supportedCredentials.map(sc => sc.exportCredentialSupportedObject())
		],
		grants: {
			authorization_code: { issuer_state: "123xxx" }
		}
	};
	const credentialOfferURL = "openid-credential-offer://?" + qs.stringify(credentialOfferObject);

	const parsed = qs.parse(credentialOfferURL.split('?')[1]);
	console.log("parsed = ", parsed)
	// credentialOfferURL.searchParams.append("credential_offer", qs.stringify(credentialOfferObject));
	
	switch (client_type) {
	case "DESKTOP":
		return res.render('issuer/init', {
			url: credentialOfferURL,
			qrcode: "",
			lang: req.lang,
			locale: locale[req.lang]
		})
	case "MOBILE":
		return res.redirect(credentialOfferURL);
	default:
		return res.redirect('/');
	}
})


// catch 404 and forward to error handler
app.use((req, _res, next) => {
	console.error("URL path not found: ", req.url)
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