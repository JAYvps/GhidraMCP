package ghidra.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * 为MCP服务器处理单独的客户端连接。
 * 这个类的每个实例都在自己的线程中运行，以管理与单个客户端的通信，
 * 处理请求并发送响应。
 */
public class MCPClientHandler implements Runnable {
    private Socket clientSocket; // 用于与客户端通信的套接字。
    private MCPContextProvider contextProvider; // 提供实际分析功能的服务。
    private Gson gson = new Gson(); // 用于JSON序列化和反序列化。

    /**
     * 构建一个新的客户端处理器。
     * @param socket 由服务器建立的客户端套接字。
     * @param provider 将执行分析任务的上下文提供者。
     */
    public MCPClientHandler(Socket socket, MCPContextProvider provider) {
        this.clientSocket = socket;
        this.contextProvider = provider;
    }

    /**
     * 客户端处理器线程的主要执行方法。
     * 它从客户端读取JSON请求，处理它们，然后发回JSON响应。
     */
    @Override
    public void run() {
        try (
            // 建立用于通信的输入和输出流。
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            String inputLine;
            // 持续从客户端读取数据，直到连接关闭。
            while ((inputLine = in.readLine()) != null) {
                // 解析传入的JSON请求。
                JsonObject request = gson.fromJson(inputLine, JsonObject.class);
                String method = request.get("method").getAsString();
                
                // 准备一个包含原始请求ID的标准响应对象。
                JsonObject response = new JsonObject();
                response.addProperty("id", request.get("id").getAsString());
                
                try {
                    // 根据"method"字段将请求路由到相应的方法。
                    switch (method) {
                        case "getContext":
                            Map<String, Object> context = contextProvider.getContext();
                            response.add("result", gson.toJsonTree(context));
                            break;
                            
                        case "getFunctionAt":
                            String address = request.get("params").getAsJsonObject().get("address").getAsString();
                            Map<String, Object> functionInfo = contextProvider.getFunctionAt(address);
                            response.add("result", gson.toJsonTree(functionInfo));
                            break;
                            
                        case "getDecompiledCode":
                            String funcAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            String decompiled = contextProvider.getDecompiledCode(funcAddr);
                            response.addProperty("result", decompiled);
                            break;
                            
                        case "analyzeBinaryForQuestion":
                            String question = request.get("params").getAsJsonObject().get("question").getAsString();
                            Map<String, Object> analysisResult = contextProvider.analyzeBinaryForQuestion(question);
                            response.add("result", gson.toJsonTree(analysisResult));
                            break;
                            
                        case "getAllFunctions":
                            Map<String, Object> allFunctions = contextProvider.getAllFunctions();
                            response.add("result", gson.toJsonTree(allFunctions));
                            break;
                            
                        case "getStrings":
                            Map<String, Object> strings = contextProvider.getStrings();
                            response.add("result", gson.toJsonTree(strings));
                            break;
                            
                        case "getImports":
                            Map<String, Object> imports = contextProvider.getImports();
                            response.add("result", gson.toJsonTree(imports));
                            break;
                            
                        case "getExports":
                            Map<String, Object> exports = contextProvider.getExports();
                            response.add("result", gson.toJsonTree(exports));
                            break;
                            
                        case "getMemoryMap":
                            Map<String, Object> memoryMap = contextProvider.getMemoryMap();
                            response.add("result", gson.toJsonTree(memoryMap));
                            break;

                        case "renameFunction":
                            String currentName = request.get("params").getAsJsonObject().get("currentName").getAsString();
                            String newFuncName = request.get("params").getAsJsonObject().get("newName").getAsString();
                            boolean funcRenamed = contextProvider.renameFunction(currentName, newFuncName);
                            response.addProperty("result", funcRenamed);
                            break;

                        case "renameData":
                            String dataAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            String newDataName = request.get("params").getAsJsonObject().get("newName").getAsString();
                            boolean dataRenamed = contextProvider.renameData(dataAddr, newDataName);
                            response.addProperty("result", dataRenamed);
                            break;

                        case "extractApiCallSequences":
                            String apiCallFuncAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            Map<String, Object> apiCallSequences = contextProvider.extractApiCallSequences(apiCallFuncAddr);
                            response.add("result", gson.toJsonTree(apiCallSequences));
                            break;

                        case "identifyUserInputSources":
                            Map<String, Object> inputSources = contextProvider.identifyUserInputSources();
                            response.add("result", gson.toJsonTree(inputSources));
                            break;

                        case "generateStructuredCallGraph":
                            String startFuncAddr = request.get("params").getAsJsonObject().get("address").getAsString();
                            int maxDepth = request.get("params").getAsJsonObject().get("maxDepth").getAsInt();
                            Map<String, Object> callGraph = contextProvider.generateStructuredCallGraph(startFuncAddr, maxDepth);
                            response.add("result", gson.toJsonTree(callGraph));
                            break;

                        case "identifyCryptographicPatterns":
                            Map<String, Object> cryptoPatterns = contextProvider.identifyCryptographicPatterns();
                            response.add("result", gson.toJsonTree(cryptoPatterns));
                            break;

                        case "findObfuscatedStrings":
                            Map<String, Object> obfuscatedStrings = contextProvider.findObfuscatedStrings();
                            response.add("result", gson.toJsonTree(obfuscatedStrings));
                            break;
                            
                        default:
                            // 通过返回错误来处理未知方法。
                            response.addProperty("error", "Unknown method: " + method);
                    }
                } catch (Exception e) {
                    // 如果在处理过程中发生任何错误，捕获它并发送错误响应。
                    response.addProperty("error", e.getMessage());
                    e.printStackTrace();
                }
                
                // 将最终的JSON响应（结果或错误）发送回客户端。
                out.println(gson.toJson(response));
            }
        } catch (IOException e) {
            // 处理与网络I/O相关的错误。
            e.printStackTrace();
        } finally {
            // 确保在处理器退出时关闭客户端套接字。
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
