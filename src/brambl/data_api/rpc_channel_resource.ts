import { Channel, ChannelCredentials } from '@grpc/grpc-js';

/**
 * A resource that provides a connection to a GRPC server.
 */
interface RpcChannelResource {
    /**
     * Creates a resource that provides a connection to a GRPC server.
     *
     * @param address the host address of the GRPC server.
     * @param port the port of the GRPC server.
     * @param secureConnection whether to use a secure connection.
     * @returns A Promise that resolves to a gRPC channel.
     */
    channelResource(
      address: string,
      port: number,
      secureConnection: boolean
    ): Promise<Channel>;
  }

/**
 * A resource that provides a connection to a GRPC server.
 */
const RpcChannelResource: RpcChannelResource = {
    channelResource: (
      address: string,
      port: number,
      secureConnection: boolean
    ): Promise<Channel> => {
      const channelPromise = new Promise<Channel>((resolve, reject) => {
        try {
          let channelCredentials: ChannelCredentials;
          if (secureConnection) {
            channelCredentials = ChannelCredentials.createSsl();
          } else {
            channelCredentials = ChannelCredentials.createInsecure();
          }
  
          const channel = new Channel(
            `${address}:${port}`,
            channelCredentials,
            undefined // TODO figure out how grpc works with channel options
          );
  
          resolve(channel);
        } catch (err) {
          reject(err);
        }
      });
  
      return channelPromise;
    },
  };

export default RpcChannelResource;
