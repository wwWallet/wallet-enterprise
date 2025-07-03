import winston from 'winston';
const { combine, timestamp, label, printf } = winston.format;

const myFormat = printf(({ level, message, label, timestamp }) => {
  return `${timestamp} [${label}] ${level}: ${message}`;
});




const logger = winston.createLogger({
  level: 'info',
  format: combine(
    label({ label: 'enterprise-app' }),
    timestamp(),
    myFormat,
		winston.format.colorize()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    //
    // - Write all logs with importance level of `error` or less to `error.log`
    // - Write all logs with importance level of `info` or less to `combined.log`
    //
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

//
// If we're not in production then log to the `console` with the format:
// `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
//
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
	  format: combine(
 	  	label({ label: 'enterprise-app' }),
    	timestamp(),
    	myFormat
  	),
  }));
}

// added code on log message for errors only (this function will not be used for 'warn' or 'info')
export const newLogerr = (errorCode: number, message: string): string => `==${errorCode}==: ${message}`;

export default logger;
