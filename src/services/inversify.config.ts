import { Container } from "inversify";
import { WalletKeystore } from "./interfaces";
import { TYPES } from "./types";
import { FilesystemKeystoreService } from "./FilesystemKeystoreService";


const appContainer = new Container();

appContainer.bind<WalletKeystore>(TYPES.FilesystemKeystoreService)
	.to(FilesystemKeystoreService);

export { appContainer }