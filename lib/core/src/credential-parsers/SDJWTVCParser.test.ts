import { assert, describe, it } from "vitest";
import { SDJWTVCParser } from "./SDJWTVCParser";
import { Context, HttpClient } from "../interfaces";
import axios, { AxiosHeaders } from "axios";
import { VerifiableCredentialFormat } from "../types";

const rawCredential = `eyJ0eXAiOiJ2YytzZC1qd3QiLCJ2Y3RtIjpbImV5SjJZM1FpT2lKbGRTNWxkWEp2Y0dFdVpXTXVaWFZrYVM1d2FXUXVNU0lzSW01aGJXVWlPaUpXWlhKcFptbGhZbXhsSUVsRUlpd2laR1Z6WTNKcGNIUnBiMjRpT2lKVWFHbHpJR2x6SUdFZ1ZtVnlhV1pwWVdKc1pTQkpSQ0JrYjJOMWJXVnVkQ0JwYzNOMVpXUWdZbmtnZEdobElIZGxiR3dnYTI1dmQyNGdWa2xFSUVsemMzVmxjaUlzSW1ScGMzQnNZWGtpT2x0N0lteGhibWNpT2lKbGJpMVZVeUlzSW01aGJXVWlPaUpXWlhKcFptbGhZbXhsSUVsRUlpd2ljbVZ1WkdWeWFXNW5JanA3SW5OcGJYQnNaU0k2ZXlKc2IyZHZJanA3SW5WeWFTSTZJbWgwZEhBNkx5OTNZV3hzWlhRdFpXNTBaWEp3Y21selpTMTJhV1F0YVhOemRXVnlPamd3TURNdmFXMWhaMlZ6TDJ4dloyOHVjRzVuSWl3aWRYSnBJMmx1ZEdWbmNtbDBlU0k2SW5Ob1lUSTFOaTFoWTJSaE16UXdOR015WTJZME5tUmhNVGt5WTJZeU5EVmpZMk0yWWpreFpXUmpaVGc0TmpreE1qSm1ZVFZoTmpZek5qSTROR1l4WVRZd1ptWmpaRGcySWl3aVlXeDBYM1JsZUhRaU9pSldTVVFnVEc5bmJ5SjlMQ0ppWVdOclozSnZkVzVrWDJOdmJHOXlJam9pSXpSall6TmtaQ0lzSW5SbGVIUmZZMjlzYjNJaU9pSWpSa1pHUmtaR0luMHNJbk4yWjE5MFpXMXdiR0YwWlhNaU9sdDdJblZ5YVNJNkltaDBkSEE2THk5M1lXeHNaWFF0Wlc1MFpYSndjbWx6WlMxMmFXUXRhWE56ZFdWeU9qZ3dNRE12YVcxaFoyVnpMM1JsYlhCc1lYUmxMbk4yWnlKOVhYMTlYU3dpWTJ4aGFXMXpJanBiZXlKd1lYUm9JanBiSW1kcGRtVnVYMjVoYldVaVhTd2laR2x6Y0d4aGVTSTZXM3NpYkdGdVp5STZJbVZ1TFZWVElpd2liR0ZpWld3aU9pSkhhWFpsYmlCT1lXMWxJaXdpWkdWelkzSnBjSFJwYjI0aU9pSlVhR1VnWjJsMlpXNGdibUZ0WlNCdlppQjBhR1VnVmtsRUlHaHZiR1JsY2lKOVhTd2ljM1puWDJsa0lqb2laMmwyWlc1ZmJtRnRaU0o5TEhzaWNHRjBhQ0k2V3lKbVlXMXBiSGxmYm1GdFpTSmRMQ0prYVhOd2JHRjVJanBiZXlKc1lXNW5Jam9pWlc0dFZWTWlMQ0pzWVdKbGJDSTZJa1poYldsc2VTQk9ZVzFsSWl3aVpHVnpZM0pwY0hScGIyNGlPaUpVYUdVZ1ptRnRhV3g1SUc1aGJXVWdiMllnZEdobElGWkpSQ0JvYjJ4a1pYSWlmVjBzSW5OMloxOXBaQ0k2SW1aaGJXbHNlVjl1WVcxbEluMHNleUp3WVhSb0lqcGJJbUpwY25Sb1gyUmhkR1VpWFN3aVpHbHpjR3hoZVNJNlczc2liR0Z1WnlJNkltVnVMVlZUSWl3aWJHRmlaV3dpT2lKQ2FYSjBhQ0JrWVhSbElpd2laR1Z6WTNKcGNIUnBiMjRpT2lKVWFHVWdZbWx5ZEdnZ1pHRjBaU0J2WmlCMGFHVWdWa2xFSUdodmJHUmxjaUo5WFN3aWMzWm5YMmxrSWpvaVltbHlkR2hmWkdGMFpTSjlMSHNpY0dGMGFDSTZXeUpwYzNOMWFXNW5YMkYxZEdodmNtbDBlU0pkTENKa2FYTndiR0Y1SWpwYmV5SnNZVzVuSWpvaVpXNHRWVk1pTENKc1lXSmxiQ0k2SWtsemMzVnBibWNnWVhWMGFHOXlhWFI1SWl3aVpHVnpZM0pwY0hScGIyNGlPaUpVYUdVZ2FYTnpkV2x1WnlCaGRYUm9iM0pwZEhrZ2IyWWdkR2hsSUZaSlJDQmpjbVZrWlc1MGFXRnNJbjFkTENKemRtZGZhV1FpT2lKcGMzTjFhVzVuWDJGMWRHaHZjbWwwZVNKOUxIc2ljR0YwYUNJNld5SnBjM04xWVc1alpWOWtZWFJsSWwwc0ltUnBjM0JzWVhraU9sdDdJbXhoYm1jaU9pSmxiaTFWVXlJc0lteGhZbVZzSWpvaVNYTnpkV0Z1WTJVZ1pHRjBaU0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hsSUdSaGRHVWdkR2hoZENCMGFHVWdZM0psWkdWdWRHbGhiQ0IzWVhNZ2FYTnpkV1ZrSW4xZExDSnpkbWRmYVdRaU9pSnBjM04xWVc1alpWOWtZWFJsSW4wc2V5SndZWFJvSWpwYkltVjRjR2x5ZVY5a1lYUmxJbDBzSW1ScGMzQnNZWGtpT2x0N0lteGhibWNpT2lKbGJpMVZVeUlzSW14aFltVnNJam9pU1hOemRXRnVZMlVnWkdGMFpTSXNJbVJsYzJOeWFYQjBhVzl1SWpvaVZHaGxJR1JoZEdVZ2RHaGhkQ0IwYUdVZ1kzSmxaR1Z1ZEdsaGJDQjNhV3hzSUdWNGNHbHlaU0o5WFN3aWMzWm5YMmxrSWpvaVpYaHdhWEo1WDJSaGRHVWlmVjE5Il0sIng1YyI6WyJNSUlCM0RDQ0FZRUNGSEJEV3BrTGk2NGY1WnJGMHh1eXRqNVBJcmJxTUFvR0NDcUdTTTQ5QkFNQ01IQXhDekFKQmdOVkJBWVRBa2RTTVE4d0RRWURWUVFJREFaQmRHaGxibk14RURBT0JnTlZCQWNNQjBsc2JHbHphV0V4RVRBUEJnTlZCQW9NQ0hkM1YyRnNiR1YwTVJFd0R3WURWUVFMREFoSlpHVnVkR2wwZVRFWU1CWUdBMVVFQXd3UGQzZDNZV3hzWlhRdGFYTnpkV1Z5TUI0WERUSTBNRGt5TmpBNE1UUXhNbG9YRFRNME1Ea3lOREE0TVRReE1sb3djREVMTUFrR0ExVUVCaE1DUjFJeER6QU5CZ05WQkFnTUJrRjBhR1Z1Y3pFUU1BNEdBMVVFQnd3SFNXeHNhWE5wWVRFUk1BOEdBMVVFQ2d3SWQzZFhZV3hzWlhReEVUQVBCZ05WQkFzTUNFbGtaVzUwYVhSNU1SZ3dGZ1lEVlFRRERBOTNkM2RoYkd4bGRDMXBjM04xWlhJd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRdFk5a1VRRmZEZjZpb2NGRTRyUnZ5M0dNeVl5cHFtWDNaam13VWVYSnkwa2tnUlQ3M0M4K1dQa1dOZy95ZEpIQ0VERE81WHVSYUlhT0hjOURwTHBOU01Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRRHp3MjduQnI3RThONkdxYzgzdi82KzlpemkvTkVYQktsb2p3TEpBZVNsc0FJaEFPMkpkalBFejNiRDBzdG9XRWc3UkR0ckFtOGRzZ3J5Q3kxVzVCREdDVmROIl0sImFsZyI6IkVTMjU2In0.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJ0SWdzMG54Z19tZUFlSk5UZnk1dW45QUFIV2hQSHBBR2t2cUh1bzJscTlFIiwieSI6Ik5EVmw1STVENnN0NVBnbmltX2lMak5VNnBLOG02SjFQQVVxbzE4UDR3TGsifX0sInZjdCI6ImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwianRpIjoidXJuOnZpZDpjN2M4ZWY0Yy0zMzQxLTRlZjEtYjMxZS0wNDM5MjE5ZGY2ODEiLCJpYXQiOjE3MzgxNjEyNDYsImV4cCI6MTc2OTY5NzI0NiwiaXNzIjoiaHR0cDovL3dhbGxldC1lbnRlcnByaXNlLXZpZC1pc3N1ZXI6ODAwMyIsInN1YiI6InpQVC1jbElMZjNIM3ozR012UTk4dUdjMmZzNVo0RkFZN0VfbDZXUVljYlkiLCJfc2RfYWxnIjoic2hhLTI1NiIsIl9zZCI6WyI4SGUtM0NmbmhOREhnaGhvMGktOXYzeDdJLXF6cE1hN29vNFNDaWxVVHBrIiwiRmZCTS02Vm94ZnFSbFNMbFNTOG1xcENFZ3JmeDhTN2ZGblkwV2FIcnVLUSIsIkgyMUhnNzRZM05uMmN2Y0FxY3JSQ0JES08ya09fRVBGWmtlS05KTnN0NzAiLCJIWW9pd1dQRTV4OV90UG9LWlc3VEU1UFRDeGxkR0Y1OHlMaXF1SlNLMkZVIiwiSWpQUGM0WUFIRFhSbjc1RnJxaTVuRVVHR1ZtdVk5dDZTQzBocE1nY3BhNCIsIm9nVV9fVzlGMzFVbF9kOEVGXzNZcVk3NFQxLTVhUGF4NXdUbng4ZmgySGsiLCJxTkM5WDYwNTE4WXh6Qlp3N1lERE9QbGZvd0poYzI2dFR2UXBzTVBualUwIiwicjh5WUhkOTJEb0tUX3hCR1F2V3lrZGUyVHJpWFRST1JtUWxFblBWRFdxUSIsInRUWmMzSExWcXNRM3ZtYXpMU2ppSlFxWUFEdVNsTGVkTjJTMTRSQzZlbzgiXX0.idvaY7ykoRjJ6DFfkjsuxu38ATX_9RZYWuOanyX7oUN0vp16eRqrxPIcVqTVJ0xuzXTHFUeMPYymWWu57wC18g~WyJ0Y282TE5iZC12Y0szRmROenhGZFpRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyIyZjJDY0ItaVpjUnRkOHpoRktsakp3IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJhMzFSV1lxOHpseHFXZDhiMGk1UlBnIiwiYmlydGhfZGF0ZSIsIjE5OTAtMTAtMTUiXQ~`;
const expiredCredential = `eyJ0eXAiOiJ2YytzZC1qd3QiLCJ2Y3RtIjpbImV5SjJZM1FpT2lKMWNtNDZZM0psWkdWdWRHbGhiRHAyYVdRaUxDSnVZVzFsSWpvaVZtVnlhV1pwWVdKc1pTQkpSQ0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hwY3lCcGN5QmhJRlpsY21sbWFXRmliR1VnU1VRZ1pHOWpkVzFsYm5RZ2FYTnpkV1ZrSUdKNUlIUm9aU0IzWld4c0lHdHViM2R1SUZaSlJDQkpjM04xWlhJaUxDSmthWE53YkdGNUlqcGJleUpzWVc1bklqb2laVzR0VlZNaUxDSnVZVzFsSWpvaVZtVnlhV1pwWVdKc1pTQkpSQ0lzSW5KbGJtUmxjbWx1WnlJNmV5SnphVzF3YkdVaU9uc2liRzluYnlJNmV5SjFjbWtpT2lKb2RIUndPaTh2ZDJGc2JHVjBMV1Z1ZEdWeWNISnBjMlV0ZG1sa0xXbHpjM1ZsY2pvNE1EQXpMMmx0WVdkbGN5OXNiMmR2TG5CdVp5SXNJblZ5YVNOcGJuUmxaM0pwZEhraU9pSnphR0V5TlRZdFlXTmtZVE0wTURSak1tTm1ORFprWVRFNU1tTm1NalExWTJOak5tSTVNV1ZrWTJVNE9EWTVNVEl5Wm1FMVlUWTJNell5T0RSbU1XRTJNR1ptWTJRNE5pSXNJbUZzZEY5MFpYaDBJam9pVmtsRUlFeHZaMjhpZlN3aVltRmphMmR5YjNWdVpGOWpiMnh2Y2lJNklpTTBZMk16WkdRaUxDSjBaWGgwWDJOdmJHOXlJam9pSTBaR1JrWkdSaUo5TENKemRtZGZkR1Z0Y0d4aGRHVnpJanBiZXlKMWNta2lPaUpvZEhSd09pOHZkMkZzYkdWMExXVnVkR1Z5Y0hKcGMyVXRkbWxrTFdsemMzVmxjam80TURBekwybHRZV2RsY3k5MFpXMXdiR0YwWlM1emRtY2lmVjE5ZlYwc0ltTnNZV2x0Y3lJNlczc2ljR0YwYUNJNld5Sm5hWFpsYmw5dVlXMWxJbDBzSW1ScGMzQnNZWGtpT2x0N0lteGhibWNpT2lKbGJpMVZVeUlzSW14aFltVnNJam9pUjJsMlpXNGdUbUZ0WlNJc0ltUmxjMk55YVhCMGFXOXVJam9pVkdobElHZHBkbVZ1SUc1aGJXVWdiMllnZEdobElGWkpSQ0JvYjJ4a1pYSWlmVjBzSW5OMloxOXBaQ0k2SW1kcGRtVnVYMjVoYldVaWZTeDdJbkJoZEdnaU9sc2labUZ0YVd4NVgyNWhiV1VpWFN3aVpHbHpjR3hoZVNJNlczc2liR0Z1WnlJNkltVnVMVlZUSWl3aWJHRmlaV3dpT2lKR1lXMXBiSGtnVG1GdFpTSXNJbVJsYzJOeWFYQjBhVzl1SWpvaVZHaGxJR1poYldsc2VTQnVZVzFsSUc5bUlIUm9aU0JXU1VRZ2FHOXNaR1Z5SW4xZExDSnpkbWRmYVdRaU9pSm1ZVzFwYkhsZmJtRnRaU0o5TEhzaWNHRjBhQ0k2V3lKaWFYSjBhRjlrWVhSbElsMHNJbVJwYzNCc1lYa2lPbHQ3SW14aGJtY2lPaUpsYmkxVlV5SXNJbXhoWW1Wc0lqb2lRbWx5ZEdnZ1pHRjBaU0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hsSUdKcGNuUm9JR1JoZEdVZ2IyWWdkR2hsSUZaSlJDQm9iMnhrWlhJaWZWMHNJbk4yWjE5cFpDSTZJbUpwY25Sb1gyUmhkR1VpZlN4N0luQmhkR2dpT2xzaWFYTnpkV2x1WjE5aGRYUm9iM0pwZEhraVhTd2laR2x6Y0d4aGVTSTZXM3NpYkdGdVp5STZJbVZ1TFZWVElpd2liR0ZpWld3aU9pSkpjM04xYVc1bklHRjFkR2h2Y21sMGVTSXNJbVJsYzJOeWFYQjBhVzl1SWpvaVZHaGxJR2x6YzNWcGJtY2dZWFYwYUc5eWFYUjVJRzltSUhSb1pTQldTVVFnWTNKbFpHVnVkR2xoYkNKOVhTd2ljM1puWDJsa0lqb2lhWE56ZFdsdVoxOWhkWFJvYjNKcGRIa2lmU3g3SW5CaGRHZ2lPbHNpYVhOemRXRnVZMlZmWkdGMFpTSmRMQ0prYVhOd2JHRjVJanBiZXlKc1lXNW5Jam9pWlc0dFZWTWlMQ0pzWVdKbGJDSTZJa2x6YzNWaGJtTmxJR1JoZEdVaUxDSmtaWE5qY21sd2RHbHZiaUk2SWxSb1pTQmtZWFJsSUhSb1lYUWdkR2hsSUdOeVpXUmxiblJwWVd3Z2QyRnpJR2x6YzNWbFpDSjlYU3dpYzNablgybGtJam9pYVhOemRXRnVZMlZmWkdGMFpTSjlMSHNpY0dGMGFDSTZXeUpsZUhCcGNubGZaR0YwWlNKZExDSmthWE53YkdGNUlqcGJleUpzWVc1bklqb2laVzR0VlZNaUxDSnNZV0psYkNJNklrbHpjM1ZoYm1ObElHUmhkR1VpTENKa1pYTmpjbWx3ZEdsdmJpSTZJbFJvWlNCa1lYUmxJSFJvWVhRZ2RHaGxJR055WldSbGJuUnBZV3dnZDJsc2JDQmxlSEJwY21VaWZWMHNJbk4yWjE5cFpDSTZJbVY0Y0dseWVWOWtZWFJsSW4xZGZRIl0sIng1YyI6WyJNSUlCM0RDQ0FZRUNGSEJEV3BrTGk2NGY1WnJGMHh1eXRqNVBJcmJxTUFvR0NDcUdTTTQ5QkFNQ01IQXhDekFKQmdOVkJBWVRBa2RTTVE4d0RRWURWUVFJREFaQmRHaGxibk14RURBT0JnTlZCQWNNQjBsc2JHbHphV0V4RVRBUEJnTlZCQW9NQ0hkM1YyRnNiR1YwTVJFd0R3WURWUVFMREFoSlpHVnVkR2wwZVRFWU1CWUdBMVVFQXd3UGQzZDNZV3hzWlhRdGFYTnpkV1Z5TUI0WERUSTBNRGt5TmpBNE1UUXhNbG9YRFRNME1Ea3lOREE0TVRReE1sb3djREVMTUFrR0ExVUVCaE1DUjFJeER6QU5CZ05WQkFnTUJrRjBhR1Z1Y3pFUU1BNEdBMVVFQnd3SFNXeHNhWE5wWVRFUk1BOEdBMVVFQ2d3SWQzZFhZV3hzWlhReEVUQVBCZ05WQkFzTUNFbGtaVzUwYVhSNU1SZ3dGZ1lEVlFRRERBOTNkM2RoYkd4bGRDMXBjM04xWlhJd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRdFk5a1VRRmZEZjZpb2NGRTRyUnZ5M0dNeVl5cHFtWDNaam13VWVYSnkwa2tnUlQ3M0M4K1dQa1dOZy95ZEpIQ0VERE81WHVSYUlhT0hjOURwTHBOU01Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRRHp3MjduQnI3RThONkdxYzgzdi82KzlpemkvTkVYQktsb2p3TEpBZVNsc0FJaEFPMkpkalBFejNiRDBzdG9XRWc3UkR0ckFtOGRzZ3J5Q3kxVzVCREdDVmROIl0sImFsZyI6IkVTMjU2In0.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJsSjlYZDR0N25IcExkSlJkaEQ1UDZ3ZVg5S1ZEeWVmWUtVcmV2V1hqd200IiwieSI6IlFjamRjR19Fd1h5Q0Ewald5UzY2Y1VWc0dTckNaVFJ3VFJwM2F2bWpGS0EifX0sInZjdCI6InVybjpjcmVkZW50aWFsOnZpZCIsImp0aSI6InVybjp2aWQ6YjU0YjNmYTItNDUyNy00MzNmLWIwYmEtYjNlN2Y0YWQyODI2IiwiaWF0IjoxNzM2OTM2NDM3LCJleHAiOjE3MzY5MzYsImlzcyI6Imh0dHA6Ly93YWxsZXQtZW50ZXJwcmlzZS12aWQtaXNzdWVyOjgwMDMiLCJzdWIiOiJ2d0dZWFNmRkhiM205c1ZuSUdiWjZhSXBGUHN5MllZLVlmdGhtOG5Cc1hzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOlsiMXJ0MTg4Umk5ZTZNZk96WnZRTHJFN0ZDSFE5c2tKNU1aVVRjVlY4WlpaayIsIkRKWVpGUXhMLU5EUEF6UnFtUmd1NnBqVzN1NUxrVm1McnFQeks5MUJlbTQiLCJlOEI3OVR2cUFLc0RPMEVEdkhFXzZoeE9CeUpScFNmRHFtS1BiNXd1dFBVIiwiaERoLXVQOWt4czJDOWk1T3hfTHlBTDIyLTFGdHdrbERhS3RxcWd6bWVYQSIsImtLRGpTc0xVbW1vQTlkUGYwMi1EQ1ZPaXBicnRkelUtWGUtNFVhRXpCWEUiLCJvWHIzT1RfdTM1TW9aNGtLXzZNMGozUHpBN1NBNFlaN19UYUFJQmYySVRNIiwieElab0JVTW53NWh4Q0F1Qi1xSXMydnBZeWxMRWhIQVdhT2NEUlpEUUtqVSIsInpRMURPT0VJd25YMG5KeVF4bklFUUhaUVJLYU9BS3JWTVZMaGxhYnJKWmciXX0.pKTd7FDZfwDNpkjKJY9YBnPlGUxga7yHhTGC-jw8jhdC1sNZgK8lMgaiHEn_PSqNXF3jIOxNPOFCJUfOu3cEfQ~WyIzRlVoRHMyMVl4Um14SjEyVm85ZnBRIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4M2xtc051UlV6U1FzM0R2Zkd6TlFnIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJxUU12TFhWRXkzUDA3QzBJdjE0Q25RIiwiYmlydGhfZGF0ZSIsIjE5OTAtMTAtMTVUMDA6MDA6MDAuMDAwWiJd~WyJ3S2h5WFZUVVdramE2ZTQ2LWtmMl93IiwiaXNzdWluZ19hdXRob3JpdHkiLCJQSUQ6MDAwMDEiXQ~WyJQWnV4S2tCbE85NjZuTkRhQkpqZy1nIiwiaXNzdWluZ19jb3VudHJ5IiwiR1IiXQ~WyJxbWtCLWRVREFXWmMzN1JHVjB6SGF3IiwiZG9jdW1lbnRfbnVtYmVyIiwiMTIzMTMyMTMiXQ~WyJUTkhyeGZJdGluU0s4aE44QU9iaGdnIiwiaXNzdWFuY2VfZGF0ZSIsIjIwMjUtMDEtMTVUMTA6MjA6MzcuNzA3WiJd~WyJ0Zk9NSkthUlBCZG9uRVFVUGQyZEV3IiwiZXhwaXJ5X2RhdGUiLDE3MzY5MzY0Mzdd~`;
const msoMdocIssuerSigned = `omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQS62BhZBLWnZnN0YXR1c6Frc3RhdHVzX2xpc3SiY2lkeBhsY3VyaXhWaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL3N0YXR1cy84ODc5M2MwMy0xNmFkLTQ0NjgtYmVmNy1jMDgzZDM4YWUyMTlnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xOFQxNDoxMjowNFppdmFsaWRGcm9twHQyMDI1LTAyLTE4VDE0OjEyOjA0Wmp2YWxpZFVudGlswHQyMDI1LTAzLTA0VDE0OjEyOjA0Wmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xtgBYIKuGxnFMGhNio5-VUJKePlkmw33mloMA9fgqUR0ynOoJAVggWxNyUrVxTPW2riSGxx_U_irluD-vcJIOGGrafGo6JpwCWCDKOCdlxlbeX7mztFkzrM7MsZHs3gEyrmC79X3N2VpxkgNYICmI6iaQPBePM7fzBXqPyX5Gr-wNnWNCNb7wDUz4VDIRBFggfCuu8bFboi9BiRPsM447Ncg9A7K7A28iTEjVy9fmjBIFWCC6z1AlQM8ttJfuIQtPYlurlamh3MvAbSaQoUzAn-9L9gZYIKD1mVbZ5zb-_sp_E6vZCQ_U2QAQVNtbWAznR4xUm6LoB1ggWAn0OSPMM-m8NbgBZ-D6qLV0BEVeSnR4DIsUPUOZDbsIWCDyTDBH9XjK_JIq_W7d19UpmMq1pd1CjrmhfIHsctg3gwlYIK7ejRc3g-pfNGM0WHv4Oh1jfshl03Jvm3cxKHFnIIXmClggjPVDgZmiJEpnM6Zo_mzUQAbW5M6QZuRH43L6BqVeT7wLWCCSVNDu2CjnRkbC7_6m6-G6h8dTDWvlmGz0WD-MUCGERwxYIDpAXdFHgnACMgICXQpJi9nzBDRjsJ8bY1htM9GtgZlKDVggvhyWJk8WGQgokFghnd9DyZKyo8b6VrfAX8WTB0vH1QkOWCBLJFY_nbKL1x-5fbJCqS1IgEn_uMm9NJm2vqorCWwwPg9YIJIg7rTS_E3HAYjcjdV6WSpgZuXa8IKo7f5aC9ibPXQzEFggc_BlS8FdmjVtSqXrA2Xh58naoO0XdTbwclGo9itNTIERWCDzIo5muAIWaawEG69bUPG4mI4pEB5dUhadaUeMUEuwIhJYIEALsAqnwl3T1nC7YtOeDj-7OEHlmcwhCZjY2Qgsr2vCE1ggwG6In0GuGqO1isPXfh2EA7-mi18JAhfumCyQUA5FpYYUWCAL6kBisfFYUIU06t2d0UeqElM-c49VrVqfgYYSIx2JpRVYICYx93c95xCPFdhE03ZlReMnLGSjT_SJgEBMeErv0VlXbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgganiJYJ0goJBbFzWZ52BDtTvTP1Fqb6k80C4UBl6JrFwiWCCWf2o4RIOTRI_UGubc0rCyIDo-o_LYRzYRnWzos3gcSm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAcBP9-i1suGc_TnH7z4Mp8jFAz2Q__4w7Ju7dDG93XWfCE15E15WYaXUnkYY80tStLInk7nEi6IqEPHJPUyWiyGpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMZbYGFhRpGZyYW5kb21Q6lwO6tOJcjKhPDMrRPrRFGhkaWdlc3RJRABsZWxlbWVudFZhbHVlGDxxZWxlbWVudElkZW50aWZpZXJsYWdlX2luX3llYXJz2BhYT6RmcmFuZG9tUBwuvU0MGGbT2h94xazpeqloZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhdpGZyYW5kb21Qo6kOsHqedb_9xHVlfCXHf2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZTUxMTQ3cWVsZW1lbnRJZGVudGlmaWVydHJlc2lkZW50X3Bvc3RhbF9jb2Rl2BhYVaRmcmFuZG9tUP6aK3BnaJ4ssYCnhgPSaZpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWZCRVJMSU5xZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2XYGFhPpGZyYW5kb21QGR_ZD_ylLFjp_gFyoXxR0WhkaWdlc3RJRARsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFWkZnJhbmRvbVByTlMf_mCOUvaECM5veox_aGRpZ2VzdElEBWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYY6RmcmFuZG9tUED3uH1EYolIFfAdQr8v6pVoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZcB0MTk2NC0wOC0xMlQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWE-kZnJhbmRvbVBucDIRMDGt1bMXZVQopw3OaGRpZ2VzdElEB2xlbGVtZW50VmFsdWX0cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzY12BhYVqRmcmFuZG9tUEQqTillqXQcpIwC8F2YOMloZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMoKXZZ4ZDwVRRL4IQ7oDEFoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTbYGFhXpGZyYW5kb21QdJ-5Oz_55VjO0LOBbnoLs2hkaWdlc3RJRApsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYa6RmcmFuZG9tUMexUIlyfvCgcIUu67OBH6doZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDItMThUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYVKRmcmFuZG9tUJ_7jstnoovdbm84Cmh2etFoZGlnZXN0SUQMbGVsZW1lbnRWYWx1ZRkHrHFlbGVtZW50SWRlbnRpZmllcm5hZ2VfYmlydGhfeWVhctgYWFmkZnJhbmRvbVAnc4IFpUS4gxjqo-1DsQNvaGRpZ2VzdElEDWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWE-kZnJhbmRvbVD0dq9e6pNoaa0e_tVlZ-hZaGRpZ2VzdElEDmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYU6RmcmFuZG9tUIurbtyPoiia4qsc62iQHIBoZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZWVFUklLQXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tUKgfL0gkbSOApy2APkdkNatoZGlnZXN0SUQQbGVsZW1lbnRWYWx1ZXBIRUlERVNUUkHhup5FIDE3cWVsZW1lbnRJZGVudGlmaWVyb3Jlc2lkZW50X3N0cmVldNgYWFGkZnJhbmRvbVA3gWJEwZz8jgsLsfRJvjMQaGRpZ2VzdElEEWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHnYGFhPpGZyYW5kb21QHSMBCaBxBPPy92dCcmoZvWhkaWdlc3RJRBJsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMdgYWFakZnJhbmRvbVB4Df01yH0SBmag1gS4xKL9aGRpZ2VzdElEE2xlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWFukZnJhbmRvbVDxOTqapogRuHVS1cLoK7z6aGRpZ2VzdElEFGxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYaaRmcmFuZG9tUOFMkL6pWaVejQQEv7_aS-loZGlnZXN0SUQVbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDMtMDRUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZQ`;

const httpClient: HttpClient = {
	async get(url, headers) {
		return axios.get(url, { headers: headers as AxiosHeaders }).then((res) => (res?.data ? { ...res.data } : {})).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
	async post(url, data, headers) {
		return axios.post(url, data, { headers: headers as AxiosHeaders }).then((res) => (res?.data ? { ...res.data } : {})).catch((err) => (err?.response?.data ? { ...err.response.data } : {}));
	},
}

const context: Context = {
	clockTolerance: 0,
	lang: 'en-US',
	subtle: crypto.subtle,
	trustedCertificates: [],
};

describe("The SDJWTVCParser", () => {

	it("should parse an vc+sd-jwt credential", async () => {
		const parser = SDJWTVCParser({ httpClient, context });

		const parsedCredential = await parser.parse({ rawCredential });
		assert(parsedCredential.success);
		assert(parsedCredential.value.validityInfo.validUntil?.toISOString() === new Date("2026-01-29T14:34:06.000Z").toISOString());
	})

	it("should detect expired vc+sd-jwt credential", async () => {
		const parser = SDJWTVCParser({ httpClient, context });
		const parsedCredential = await parser.parse({ rawCredential: expiredCredential });
		assert(parsedCredential.success);
	})


	it("should handle the case of invalid format", async () => {
		const parser = SDJWTVCParser({ httpClient, context });
		const parsedCredential = await parser.parse({ rawCredential: msoMdocIssuerSigned });
		assert(parsedCredential.success === false);
	})
})
