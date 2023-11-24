import express, { Express, Request, Response } from 'express';
import config from '../config';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import cors from 'cors';
import { LanguageMiddleware } from './middlewares/language.middleware';
import { authorizationRouter } from './authorization/router';
import AppDataSource, { initDataSource } from './AppDataSource';
import createHttpError, { HttpError} from 'http-errors';
import { appContainer } from './services/inversify.config';
import { FilesystemKeystoreService } from './services/FilesystemKeystoreService';
import { authorizationServerMetadataConfiguration } from './authorizationServiceConfiguration';
import { CredentialReceivingService } from './services/CredentialReceivingService';
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

initDataSource();

const credentialReceivingService = appContainer.resolve(CredentialReceivingService);

const walletKeystore = appContainer.resolve(FilesystemKeystoreService);
// const credentialIssuersConfigurationService = appContainer.get<CredentialIssuersConfiguration>(TYPES.CredentialIssuersConfiguration);

const app: Express = express();




app.use(cors({ credentials: true, origin: true }));
// __dirname is "/path/to/dist/src"
app.use(express.static(path.join(__dirname, '../../public')));

app.use(cookieParser());
app.use(session({ secret: config.appSecret, cookie: { expires: new Date(Date.now() + (30 * 86400 * 1000)) }}))


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
	
	req.session.authenticationChain = {};
	return res.render('index', {
    title: titles.index,
		lang: req.lang,
		locale: locale[req.lang]
	})
});


app.post('/', async (req, res) => {
	await createNewAuthorizationServerState({req, res});
	req.authorizationServerState.grant_type = GrantType.PRE_AUTHORIZED_CODE;
	await AppDataSource.getRepository(AuthorizationServerState)
		.save(req.authorizationServerState);

	if (req.body.initiate_pre_authorized == "true") {
		return res.redirect(CONSENT_ENTRYPOINT);
	}
	else if (req.body.verifier == "true") {
		return res.redirect('/verifier/public/definitions');
	}

})


app.get('/.well-known/openid-configuration', async (_req: Request, res: Response) => {
	res.send(authorizationServerMetadataConfiguration); 
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