/**
 * removes _ underscore 
 * @param obj 
 * @returns 
 */
export function serializePresentationDefinition(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(serializePresentationDefinition);
  } else if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj)
        .filter(([key, _]) => !key.startsWith('_'))
        .map(([key, value]) => [key, serializePresentationDefinition(value)])
    );
  }
  return obj;
}