import { Err, Ok, Result } from "ts-results";
import { ConvertDateErrors } from "../types/errors/date.errors";

export function addSeconds(date: Date, numOfSeconds: number) {
  date.setSeconds(date.getSeconds() + numOfSeconds);
  return date;
}

function isValid8DigitDate(date: string): {value: boolean, err: ConvertDateErrors} {
	
	if (date.length != 8) {
		return {value: false, err: 'INVALID_DATE_LENGTH'};
	}

	const year: string = date.slice(0, 4);
	if(isNaN(+year))
		return {value: false, err: 'INVALID_YEAR_VALUE'};

	const month: string = date.slice(4, 6);
	if(isNaN(+month))
		return {value: false, err: 'INVALID_MONTH_VALUE'};

	const day: string = date.slice(6, 8);
	if(isNaN(+day))
		return {value: false, err: 'INVALID_DAY_VALUE'};
	
	return {value: true, err: ''};
}

/**
	 * 
	 * @param date 8 digit date string (YYYYMMDD)
	 * @returns string
	 */
 export function convert8DigDateToDashed(date: string): Result<string, ConvertDateErrors> {

	const validate8DigDate: {value: boolean, err: ConvertDateErrors} = isValid8DigitDate(date);

	if(!validate8DigDate.value)
		return Err(validate8DigDate.err);

	const year: string = date.slice(0, 4);
	const month: string = date.slice(4, 6);
	const day: string = date.slice(6, 8);

	return Ok(`${year}-${month}-${day}`);
}

/**
 * 
 * @param date 8 digit date string (YYYYMMDD)
 * @returns string
 */
export function convert8DigDateToISO (date: string): Result<string, ConvertDateErrors> {

	const validate8DigDate: {value: boolean, err: ConvertDateErrors} = isValid8DigitDate(date);

	if(!validate8DigDate.value)
		return Err(validate8DigDate.err);

	const year: string = date.slice(0, 4);
	const month: string = date.slice(4, 6);
	const day: string = date.slice(6, 8);

	return Ok(new Date(+year, (+month) - 1, +day).toISOString());
}