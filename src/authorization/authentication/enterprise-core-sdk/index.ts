import axios, { AxiosError } from "axios";
import { randomUUID } from "crypto";
import { NextFunction, Request, Response } from "express";
import { Store } from "express-session";
// import { Store } from "express-session";

export type UserInfoProfileResponse = {
	profiles: {
		issuer: string;
		issuanceDate: string;
		schemaName: string;
		claims: any;
	}[]
}

export type EnterpriseCoreSDK = {
	enterpriseCoreBaseUrl: string,
	enterpriseCoreUser: string,
	enterpriseCoreSecret: string,
	presentationDefinitionName: string,
	callbackUrl: string,
	store: Store,
	authguardCallback: (req: Request, res: Response, next: NextFunction, userinfo: UserInfoProfileResponse) => void,
}


export const initiateVerificationFlowEndpoint = (sdk: EnterpriseCoreSDK, initiationCallback: (req: Request, res: Response, url: string) => Promise<void>) => {
	return async (req: Request, res: Response) => {
		console.log("Initiating flow...")
		const state = randomUUID();
		const userSessionId = randomUUID();
		console.log("User session id = ", userSessionId)
		res.cookie(`urn:enterprise-core:session`, userSessionId);
		sdk.store.set(`urn:enterprise-core:session:${userSessionId}`, {state: state} as any);
	
		// session management
		const initiationEndpointUrl = `${sdk.enterpriseCoreBaseUrl}/verify/initiate`;
		const basicB64Token = Buffer.from(sdk.enterpriseCoreUser+":"+sdk.enterpriseCoreSecret).toString("base64");
		const body = {
			presentationDefinitionName: sdk.presentationDefinitionName,
			verificationCallbackUrl: sdk.callbackUrl,
			state: state
		};
		try {
			const result = await axios.post(initiationEndpointUrl, body, { headers: {
				authorization: `Basic ${basicB64Token}`
			}})
			const { url } = result.data;
			initiationCallback(req, res, url)
		}
		catch(err: any) {
			if (err instanceof AxiosError)
				console.log("Response error = ", err.response?.data);

			console.log("Failed to POST in the initiation endpoint")
			return res.status(500).send("Failed to  POST in the initiation endpoint")
		}

	}

}



export const verificationCallbackEndpoint = (sdk: EnterpriseCoreSDK) => {
	return (req: Request, res: Response, next: NextFunction) => {
		const userSessionId = req.cookies[`urn:enterprise-core:session`];
		console.log("User session id on callback = ", userSessionId)
		const basicB64Token = Buffer.from(sdk.enterpriseCoreUser+":"+sdk.enterpriseCoreSecret).toString("base64");
		
		const codeParam = req.query['code'] as string | null;
		const stateParam = req.query['state'] as string | null;
		const profileEndpointUrl = `${sdk.enterpriseCoreBaseUrl}/verify/profile?code=${codeParam}`;
	
		if (!codeParam) {
			console.error("Code not found")
			return res.status(500).send("Code not found")
		}
	
		if (!stateParam) {
			console.error("State not found")
			return res.status(500).send("State not found")
		}
	
	
		sdk.store.get(`urn:enterprise-core:session:${userSessionId}`, (err, session) => {
			if (err) {
				console.error("Error : ", err);
				return;
			}
	
			if (!session) {
				console.error("No session found")
				return;
			};
	
			const { state } = session as any;

			if (state != stateParam) {
				console.error("State = ", state)
				console.error("State param = ", stateParam)
				console.error("Different states")
				return;
			}
			axios.get(profileEndpointUrl, {
				headers: { authorization: `Basic ${basicB64Token}` }
			}).then(success => {
				const userinfo = success.data;
				console.log("User info received = ")
				console.dir(userinfo, {depth: null})
				sdk.store.set(`urn:enterprise-core:session:${userSessionId}`, { userinfo } as any); // store user info in session
				next();
			}).catch((err) => {
				console.log(err)
				console.error("Failed to get user info. More details");
				next();
			});
	
		})
	}
}


export const vidAuthGuard = (sdk: EnterpriseCoreSDK, errorCallback: (req: Request, res: Response) => Promise<void>) => {
	return async (req: Request, res: Response, next: NextFunction) => {
		const userSessionId = req.cookies[`urn:enterprise-core:session`];
		sdk.store.get(`urn:enterprise-core:session:${userSessionId}`, (err, session) => {
			if (err) return errorCallback(req, res);
			if (!session) return errorCallback(req, res);
			console.log("Session = ", session)
			const { userinfo } = session as any;
			sdk.authguardCallback(req, res, next, userinfo)
			console.log("Authguard called")
		})
	}
}


