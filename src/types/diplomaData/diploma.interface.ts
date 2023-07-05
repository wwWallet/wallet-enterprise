import { TitleInterface } from "./title.interface"

export interface DiplomaWithTINInterface {
	ssn: string,
	diploma: DiplomaInterface
}

export interface DiplomaInterface {
	certificate_Id: string,  // is primary key
	// the following can be changed
	SSN: string,
	Student_Id: string,
	Grade_Value: number,
	Grade_Description: string,
	Date_Issued: string,
	Valid_From: string,
	Firstname: string,
	Middlename: string,
	Lastname: string,
	Fathername: string,
	Birthdate: string,
	Title_Id: string,
	Timestamp: number,
}

export interface DiplomaWithTitleInterface {
	diploma: DiplomaInterface
	title: TitleInterface
}