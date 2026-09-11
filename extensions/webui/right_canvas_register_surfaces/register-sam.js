export default async function registerSam(surfaces) {
  surfaces.registerSurface({ id: "sam-observatory", title: "Mesh Observatory", icon: "hub",
    order: 45, modalPath: "/plugins/sam_mesh/webui/observatory.html" });
}
