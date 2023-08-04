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
import { issuersConfigurations, vidIssuer } from './configuration/IssuersConfiguration';
import createHttpError, { HttpError} from 'http-errors';
import { appContainer } from './services/inversify.config';
import { FilesystemKeystoreService } from './services/FilesystemKeystoreService';
import { authorizationServerMetadataConfiguration } from './authorizationServiceConfiguration';
import { verificationRouter } from './verification/router';
import { CredentialReceivingService } from './services/CredentialReceivingService';

AppDataSource // used for the initizlization of the DB

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


// expose all public keys
app.get('/jwks', async (_req: Request, res: Response) => {
	const { keys } = await walletKeystore.getAllPublicKeys();
	res.send({ keys });
})

app.get('/init', async (_req, res) => {
	credentialReceivingService.sendAuthorizationRequest();
	res.send({})
})

app.use(LanguageMiddleware);
app.use(UserSessionMiddleware);



app.get('/', async (req: Request, res: Response) => {
	res.render('index', {
		title: "Index",
		credentialIssuerIdentifier: vidIssuer.credentialIssuerIdentifier,
		lang: req.lang,
		locale: locale[req.lang]
	})
});

app.use('/authorization', authorizationRouter);
app.use('/openid4vci', openid4vciRouter);
app.use("/verification", verificationRouter);


for (const [_, v] of issuersConfigurations) {
	v.exposeConfiguration(app);
}




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