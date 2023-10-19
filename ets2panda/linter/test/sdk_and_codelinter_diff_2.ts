//test for defect 14029

export async function getData() {
  let datas
  let data: Object[] = []
  data.forEach(()=>{
    datas.push(1);
  })
  return datas
}