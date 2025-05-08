import express, { Express, Request, Response } from 'express';
import { config } from '../config';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import cors from 'cors';
import { LanguageMiddleware } from './middlewares/language.middleware';
import { authorizationRouter } from './authorization/router';
import AppDataSource, { initDataSource } from './AppDataSource';
import createHttpError, { HttpError } from 'http-errors';
import { appContainer } from './services/inversify.config';
import { ExpressAppService } from './services/ExpressAppService';
import { authorizationServerStateMiddleware, createNewAuthorizationServerState } from './middlewares/authorizationServerState.middleware';
import { CONSENT_ENTRYPOINT } from './authorization/constants';
import session from 'express-session';

import { verifierPanelRouter } from './verifier/verifierPanelRouter';
import locale from './configuration/locale';
import titles from './configuration/titles';

import { verifierRouter } from './verifier/verifierRouter';
import { GrantType } from './types/oid4vci';
import { AuthorizationServerState } from './entities/AuthorizationServerState.entity';
import { credentialConfigurationRegistryService, openidForCredentialIssuingAuthorizationServerService, openidForPresentationReceivingService } from './services/instances';
import _ from 'lodash';
import * as qrcode from 'qrcode';
import { configurationExecution } from './configuration/main';

const app: Express = express();

initDataSource().then(() => {
	configurationExecution();
});


app.use(cors({ credentials: true, origin: true }));
// __dirname is "/path/to/dist/src"
app.use(express.static(path.join(__dirname, '../../public')));

app.use(cookieParser());
app.use(session({ secret: config.appSecret, cookie: { expires: null, maxAge: 3600 * 1000 } }))


app.use(bodyParser.urlencoded({ extended: true })); // support url encoded bodies
app.use(bodyParser.json()); // support json encoded bodies

app.set('view engine', 'pug');




// __dirname is "/path/to/dist/src"
// public is located at "/path/to/dist/src"
app.set('views', path.join(__dirname, '../../views'));



appContainer.resolve(ExpressAppService).configure(app);




app.use(LanguageMiddleware);
app.use(authorizationServerStateMiddleware);



app.use('/verifier-panel', verifierPanelRouter);
app.use('/verifier', verifierRouter);



app.use('/authorization', authorizationRouter);

app.get('/', async (req: Request, res: Response) => {

	if (config?.appType === 'VERIFIER') {

		return res.render("indexVerifier", {
			title: titles.index,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	return res.render("landing", {
		title: titles.index,
		lang: req.lang,
		locale: locale[req.lang],
		baseUrl: config.url,
		supportedCredentials: credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().map((sc) => sc.exportCredentialSupportedObject()),
	})
})

app.get('/offer/:scope', async (req: Request, res: Response) => {
	const scope = req.params.scope;
	const supportedCredentialConfig = credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().filter((sc) => sc.getScope() == scope)[0];
	if (supportedCredentialConfig) {

		const supportedCredentialType = supportedCredentialConfig.exportCredentialSupportedObject();

		req.session.authenticationChain = {};
		const result = await openidForCredentialIssuingAuthorizationServerService.generateCredentialOfferURL({ req, res }, [supportedCredentialConfig.getId()]);

		let credentialOfferQR = await new Promise((resolve) => {
			qrcode.toDataURL(result.url.toString().replace(config.wwwalletURL, "openid-credential-offer://"), {
				margin: 1,
				errorCorrectionLevel: 'L',
				type: 'image/png'
			},
				(err, data) => {
					if (err) return resolve("NO_QR");
					return resolve(data);
				});
		}) as string;


		return res.render("index", {
			title: titles.index,
			credentialOfferURL: result.url,
			credentialOfferQR,
			supportedCredentialType,
			lang: req.lang,
			locale: locale[req.lang]
		})
	}
});

app.post('/', async (req, res) => {
	await createNewAuthorizationServerState({ req, res });
	req.authorizationServerState.grant_type = GrantType.AUTHORIZATION_CODE;
	await AppDataSource.getRepository(AuthorizationServerState)
		.save(req.authorizationServerState);

	if (req.body.initiate_pre_authorized == "true") {
		return res.redirect(CONSENT_ENTRYPOINT);
	}
	else if (req.body.verifier == "true") {
		return res.redirect('/verifier/public/definitions');
	}

})



// app.post('/demo/generate-credential-offer', async (req: Request, res: Response) => {
// 	try {
// 		const {
// 			credential_issuer_identifier,
// 			credential_configuration_id,
// 			ssn,
// 			personalIdentifier,
// 			taxis_id,
// 		} = req.body;
// 		await createNewAuthorizationServerState({ req, res });
// 		req.authorizationServerState.credential_issuer_identifier = credential_issuer_identifier;
// 		req.authorizationServerState.grant_type = GrantType.PRE_AUTHORIZED_CODE;


// 		const supportedCredential = credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().filter((credConf) => credConf.getId() == credential_configuration_id)[0]


// 		if (!supportedCredential) {
// 			return res.status(404).send({ msg: "Supported credential not found" });
// 		}

// 		const supportedCredentialObject = supportedCredential.exportCredentialSupportedObject()
// 		req.authorizationServerState.credential_configuration_ids = [ supportedCredential.getId() ];
// 		console.log("Supported credential = ", supportedCredentialObject);

// 		req.authorizationServerState.ssn = ssn;
// 		req.authorizationServerState.taxis_id = taxis_id;
// 		req.authorizationServerState.personalIdentifier = personalIdentifier;

// 		await AppDataSource.getRepository(AuthorizationServerState)
// 			.save(req.authorizationServerState);


// 		const { url, user_pin, user_pin_required } = await openidForCredentialIssuingAuthorizationServerService.generateCredentialOfferURL({ req, res }, req.authorizationServerState.credential_configuration_ids, GrantType.PRE_AUTHORIZED_CODE);
// 		res.status(200).send({ url, user_pin, user_pin_required });
// 	} catch (e) {
// 		console.log(e);
// 		return res.status(404).send({ msg: "Issuer not found" });
// 	}
// })


app.post('/demo/presentation-request', async (req: Request, res: Response) => {
	const { presentation_definition_id, callback_url } = req.body;
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentation_definition_id, callback_url);
	res.send({ url });
});

app.get('/metadata/:filename', (req, res) => {
	if (req.params.filename !== 'site.webmanifest') {
		return res.status(404).send();
	}
	const manifest = {
    name: config.siteConfig.name,
    short_name: config.siteConfig.short_name,
    start_url: "/",
    display: "standalone",
    background_color: config.siteConfig.background_color,
    theme_color: config.siteConfig.theme_color,
    icons: [
      {
        src: "/images/favicon-192x192.png",
        sizes: "192x192",
        type: "image/png"
      },
      {
        src: "/images/favicon-512x512.png",
        sizes: "512x512",
        type: "image/png"
      }
    ]
  };

  res.setHeader('Content-Type', 'application/manifest+json');
  return res.send(manifest);
});



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