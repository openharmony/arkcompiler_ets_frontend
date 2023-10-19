//test for defect 14029

import {getData} from "./sdk_and_codelinter_diff_2"
async function getDatas() {
  try {
    let data: Object[] = await getData()
  } catch (err){
  }
}