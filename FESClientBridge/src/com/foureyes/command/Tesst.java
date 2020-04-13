package com.foureyes.command;

import java.util.logging.Level;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

import com.foureyes.exception.DecodeHashException;
import com.foureyes.security.X509EncodedKeySpec;
import com.foureyes.thread.JSONRepackageDataSending;
import com.foureyes.utilities.BroadcastPane;

import io.socket.client.Socket;

public class Tesst implements CommandExecutor {

	public static Socket socket;
	
	@Override
	public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
		if (cmd.getName().equalsIgnoreCase("testsocket")) {
			try {
//				String string = "string";
//				String hashed = X509EncodedKeySpec.getRSAEncodingToString(string);
//				Bukkit.getLogger().log(Level.INFO, "Encoded : " + hashed);
//				try {
//					Bukkit.getLogger().log(Level.INFO,
//							"Decoded : " + X509EncodedKeySpec.getRSADecodingToString(hashed));
//				} catch (DecodeHashException e1) {
//					e1.printStackTrace();
//				}

				socket.connect();
				new JSONRepackageDataSending().start();
				socket.emit("Connect", Bukkit.getServer().getIp(), "test");
				socket.on("Result", new io.socket.emitter.Emitter.Listener() {

					@Override
					public void call(Object... args) {
						Bukkit.getLogger().log(Level.INFO, args[0].toString());
					}
				});
//				try {
//					socket.emit("PublicKey", X509EncodedKeySpec.getPublicKeyString());
//					Bukkit.getLogger().info(X509EncodedKeySpec.getPublicKeyString());
//					Bukkit.getLogger().info(X509EncodedKeySpec.getPrivateKeyString());
//					socket.on("Key", new io.socket.emitter.Emitter.Listener() {
//
//						@Override
//						public void call(Object... args) {
//							Bukkit.getLogger().log(Level.INFO, args[0].toString());
//						}
//					});
//				} catch (Exception e) {
//					e.printStackTrace();
//				}
				socket.on("Content", new io.socket.emitter.Emitter.Listener() {

					@Override
					public void call(Object... args) {
						try {
							Bukkit.getLogger().log(Level.INFO, args[0].toString());
							Bukkit.getLogger().log(Level.INFO,
									X509EncodedKeySpec.getRSADecodingToString(args[0].toString()));
						} catch (DecodeHashException e) {
							e.printStackTrace();
							BroadcastPane.showErrorAndContact(Bukkit.getPluginManager().getPlugin("FESClientBridge"),
									"Chúng tôi không thể giải mã dữ liệu được gửi đến bởi cloud ! Đây có thể là vấn đề "
											+ "liên quan đến hệ thống ! Hãy liên hệ với chúng tôi để kịp thời sửa chữa.");
						}
					}
				});
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return true;
	}

}
